# Smokeless Flame
A work in progress command and control framework.

The Controller communicates with many implants over DNS. The implants beacon to the server periodically waiting for commands. Active sessions are stored and inactive sessions are automatically pruned. As of now, the controller has the ability to send arbitrary commands to Windows and Linux agents and recieve the result of the commands. The controller can either specify by implant ID or command all implants to carry out the same command. 

<img width="779" height="955" alt="image" src="https://github.com/user-attachments/assets/62dbd4a9-bc1a-4776-b61f-7a7d7d1ff25c" />

Key design features are for the implants to be non-intrusive to its host and remain undetected. Current use cases would be to proxy commands through impants and quietly efiltrate data from implant devices.

## Development plans
The plan is to (in order):
- Add more data to ImplantSession struct to have the ability to get host system information and make this data persist locally serverside and loaded each time the server starts. 
- Implement more controls for the server over the implants such as being able to tweak agent beacon times and type per implant or in a batch. 
- Implement comms over other protocols. Namely HTTPS (wolf in sheep's clothing - use trusted TCP connection)
- Implement more creative communications through public and free web services. Allowing the implants to fallback on DNS if there is an issue with primary comms.
- Build implant binaries to support more devices like the already started ESP32-S3 implementation. This could take a bite at the IOT world - where the S in IOT stands for security!
- Build an example loader/dropper that is the initial exploitation
- Implant code obfuscation script
- GUI? 
