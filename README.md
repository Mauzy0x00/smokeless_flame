# Smokeless Flame
A work in progress command and control framework.

The Controller communicates with many implants over DNS. The implants beacon to the server periodically waiting for commands. Active sessions are stored and inactive sessions are automatically pruned. As of now, the controller has the ability to send arbitrary commands to Windows and Linux agents and recieve the result of the commands. The controller can either specify by implant ID or command all implants to carry out the same command. 

<img width="779" height="955" alt="image" src="https://github.com/user-attachments/assets/62dbd4a9-bc1a-4776-b61f-7a7d7d1ff25c" />
