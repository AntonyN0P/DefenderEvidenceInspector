# DefenderEvidenceInspector

**Defender Evidence Inspector** is a powerful C# tool designed to assist digital forensics and incident response teams by extracting and analyzing key evidence from Microsoft Windows Defender during cybersecurity incidents. It allows users to decrypt and parse Defender’s internal files, providing critical metadata like detection timestamps, threat names, and file paths, which are essential for thorough investigations.
The tool can also decrypt malicious files stored by Defender and retrieve important details such as file timestamps (Last Write Time, Creation Time, Last Access Time). Investigators can extract and decrypt this data from both the default Windows Defender directories or any specified location using simple command-line flags.

### Output parsed metadata Example 
    Defender Detection TimeStamp: 2024-08-27T21:37:57.562Z
    Threat ID: 2147894476
    Threat Detection Name: VirTool:MSIL/SharpDAPI!pz
    Malicious file detection path: \\?\C:\Users\AntonyN0p\Desktop\SharpDPAPI-master\SharpChrome\bin\Debug\SharpChrome.exe
    ResourceID: 52FF787E763CFCBF06EFC9C8CD336BE0CF97B9D6
    DetectionPath: C:\Users\AntonyN0p\Desktop\SharpDPAPI-master\SharpChrome\bin\Debug\SharpChrome.exe
    Creation Time: 28.08.2024 0:37:27
    LastWrite Time: 28.08.2024 0:37:27
    LastAccess Time: 28.08.2024 0:37:45

#### Defender Evidence Inspector Command Line Usage
    ██████╗░███████╗███████╗███████╗███╗░░██╗██████╗░███████╗██████╗░
    ██╔══██╗██╔════╝██╔════╝██╔════╝████╗░██║██╔══██╗██╔════╝██╔══██╗
    ██║░░██║█████╗░░█████╗░░█████╗░░██╔██╗██║██║░░██║█████╗░░██████╔╝
    ██║░░██║██╔══╝░░██╔══╝░░██╔══╝░░██║╚████║██║░░██║██╔══╝░░██╔══██╗
    ██████╔╝███████╗██║░░░░░███████╗██║░╚███║██████╔╝███████╗██║░░██║
    ╚═════╝░╚══════╝╚═╝░░░░░╚══════╝╚═╝░░╚══╝╚═════╝░╚══════╝╚═╝░░╚═╝
    ███████╗██╗░░░██╗██╗██████╗░███████╗███╗░░██╗░█████╗░███████╗
    ██╔════╝██║░░░██║██║██╔══██╗██╔════╝████╗░██║██╔══██╗██╔════╝
    █████╗░░╚██╗░██╔╝██║██║░░██║█████╗░░██╔██╗██║██║░░╚═╝█████╗░░
    ██╔══╝░░░╚████╔╝░██║██║░░██║██╔══╝░░██║╚████║██║░░██╗██╔══╝░░
    ███████╗░░╚██╔╝░░██║██████╔╝███████╗██║░╚███║╚█████╔╝███████╗
    ╚══════╝░░░╚═╝░░░╚═╝╚═════╝░╚══════╝╚═╝░░╚══╝░╚════╝░╚══════╝
    ██╗███╗░░██╗░██████╗██████╗░███████╗░█████╗░████████╗░█████╗░██████╗░
    ██║████╗░██║██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗
    ██║██╔██╗██║╚█████╗░██████╔╝█████╗░░██║░░╚═╝░░░██║░░░██║░░██║██████╔╝
    ██║██║╚████║░╚═══██╗██╔═══╝░██╔══╝░░██║░░██╗░░░██║░░░██║░░██║██╔══██╗
    ██║██║░╚███║██████╔╝██║░░░░░███████╗╚█████╔╝░░░██║░░░╚█████╔╝██║░░██║
    ╚═╝╚═╝░░╚══╝╚═════╝░╚═╝░░░░░╚══════╝░╚════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝
    By Anton Kuznetsov a.k.a AntoyN0p
    Personal Blog > https://antonyn0p.github.io/
    Git > https://github.com/AntonyN0P
    Telegram > https://t.me/RussianF0rensics
    Help:
    --------
    Usage: DefenderEvidenceInspector.exe [options]

    Options:
       --help                        Display this message
       --edir=<Path>                 Path to Quarantine entries files
       --rdatadir=<Path>             Path to Quarantine ResourceData. In other words: path to encrypted maliciuos files in quarantine
       --targetdecrypt=<Path>        Path to single Quarantine ResourceData for decryption. File will decrypt with the same of program directory. For specify recover directory use --outdir flag.
       --outdir=<Path>               Path to directory where encrypted files would be decrypted.
       --default                     Gather and parse evidencies on entire host. !!!Requires local Administrator privileges!!!

#### Default mode (REQUIRES LOCAL Administrator privileges)
    DefenderEvidenceInspector.exe --default
In default mode, Defender Evidence Inspector extracts encrypted entries and quarantined malicious files from Windows Defender's standard quarantine directories, decrypting them to the current folder or a user-specified directory. Running the tool as Administrator is optional but enhances functionality. For instance, to extract and decrypt data by default, run the above command.


#### TargetDecrypt mode
    DefenderEvidenceInspector.exe --targetdecrypt=C:\Path\99784D91C247C61AE0D31C5DDA852E37B0A10941 --outdir="C:\Users\User\Desktop\Defender Quarantine Files\decryptedmalware"
    
Decrypt to specified extracted ResourceData file (--outdir is optional). Doesn't require Administrator privs.
    

#### Parse early extracted Entries and ResourceData
    DefenderEvidenceInspector.exe --edir="C:\Users\User\Desktop\Defender Quarantine Files\Entries" --rdatadir="C:\Users\User\Desktop\Defender Quarantine Files\ResourceData" --outdir="C:\Users\User\Desktop\Defender Quarantine Files\decryptedmalware"
    
No elevated privileges are required to decrypt previously extracted files or work with specified directories. You can use flags such as --edir= and --rdatadir= to specify source directories and optionally --outdir= to determine where decrypted files should be saved.


#### Video

https://github.com/user-attachments/assets/1565ace4-78da-4a0f-8f56-2071ac9dc2f6






