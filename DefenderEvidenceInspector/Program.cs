using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;



public enum FIELD_TYPE : ushort
{
    STRING = 0x1,
    WSTRING = 0x2,
    DWORD = 0x3,
    RESOURCE_DATA = 0x4,
    BYTES = 0x5,
    QWORD = 0x6,
}

public enum FIELD_IDENTIFIER : ushort
{
    CQuaResDataID_File = 0x02,
    CQuaResDataID_Registry = 0x03,
    Flags = 0x0A,
    PhysicalPath = 0x0C,
    DetectionContext = 0x0D,
    Unknown = 0x0E,
    CreationTime = 0x0F,
    LastAccessTime = 0x10,
    LastWriteTime = 0x11
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct QuarantineEntryFileHeader
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] MagicHeader;     // CHAR MagicHeader[4];

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] Unknown;         // CHAR Unknown[4];

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] Padding;         // CHAR _Padding[32];

    public uint Section1Size;      // DWORD Section1Size;
    public uint Section2Size;      // DWORD Section2Size;
    public uint Section1CRC;       // DWORD Section1CRC;
    public uint Section2CRC;       // DWORD Section2CRC;

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] MagicFooter;     // CHAR MagicFooter[4];
};


[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct QuarantineEntrySection1
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] Id;              // CHAR Id[16];

    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] ScanId;          // CHAR ScanId[16];

    public ulong Timestamp;        // QWORD Timestamp;
    public ulong ThreatId;         // QWORD ThreatId;
    public uint One;               // DWORD One;

    //public byte[] DetectionName;
};


public class QuarantineEntrySection2_
{
    public uint EntryCount { get; set; }
    public uint[] EntryOffsets { get; set; }

    public QuarantineEntrySection2_(byte[] section2Bytes)
    {
        using (MemoryStream ms = new MemoryStream(section2Bytes))
        using (BinaryReader reader = new BinaryReader(ms))
        {
            EntryCount = reader.ReadUInt32();

            EntryOffsets = new uint[EntryCount];

            for (int i = 0; i < EntryCount; i++)
            {
                EntryOffsets[i] = reader.ReadUInt32();
            }
        }
    }

}

public class QuarantineEntryResourceField
{
    public FIELD_IDENTIFIER identifier { get; private set; }
    public FIELD_TYPE Type { get; private set; }
    public ushort Size { get; private set; }
    public byte[] Data { get; private set; }


    public QuarantineEntryResourceField(BinaryReader reader)
    {
        Size = reader.ReadUInt16();
        ushort identifierAndType = reader.ReadUInt16();
        identifier = (FIELD_IDENTIFIER)(identifierAndType & 0x0FFF);
        Type = (FIELD_TYPE)((identifierAndType >> 12) & 0xF);
        Data = reader.ReadBytes(Size);
    }
}

class QuarantineEntryResource
{
    public string DetectionPath { get; set; }
    public ushort FieldCount { get; set; }
    public string DetectionType { get; set; }
    public string ResourceId { get; set; }

    public DateTime? CreationTime { get; set; }

    public DateTime? LastAccessTime { get; set; }
    public DateTime? LastWriteTime { get; set; }
    public List<QuarantineEntryResourceField> UnknownFields { get; set; } = new List<QuarantineEntryResourceField>();

    public ushort fieldCount;

    public QuarantineEntryResource(BinaryReader reader, ushort fieldCount)
    {
        this.fieldCount = fieldCount;

        long offset = reader.BaseStream.Position;
        for (int i = 0; i < fieldCount; i++)
        {
            offset = (offset + 3) & 0xFFFFFFFC;
            reader.BaseStream.Seek(offset, SeekOrigin.Begin);

            var field = new QuarantineEntryResourceField(reader);
            AddField(field);

            offset += 4 + field.Size;
        }
    }

    private void AddField(QuarantineEntryResourceField field)
    {
        switch ((FIELD_IDENTIFIER)field.identifier)
        {
            case FIELD_IDENTIFIER.CQuaResDataID_File:
                ResourceId = BitConverter.ToString(field.Data).Replace("-", "").ToUpper();
                break;

            case FIELD_IDENTIFIER.PhysicalPath:
                DetectionPath = Encoding.Unicode.GetString(field.Data).TrimEnd('\0');
                break;

            case FIELD_IDENTIFIER.CreationTime:
                CreationTime = DateTime.FromFileTime(BitConverter.ToInt64(field.Data, 0));
                break;

            case FIELD_IDENTIFIER.LastAccessTime:
                LastAccessTime = DateTime.FromFileTime(BitConverter.ToInt64(field.Data, 0));
                break;

            case FIELD_IDENTIFIER.LastWriteTime:
                LastWriteTime = DateTime.FromFileTime(BitConverter.ToInt64(field.Data, 0));
                break;

            default:
                UnknownFields.Add(field);
                break;
        }

    }

    class Program
    {
        // The hardcoded static RC4 key 
        static readonly byte[] key = new byte[]
            {
            0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69, 0x70, 0x2C, 0x0C,
            0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7, 0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83,
            0x53, 0x0F, 0xB3, 0xFC, 0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD,
            0x0F, 0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96, 0x97, 0x90,
            0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4, 0x8E, 0x23, 0xD0, 0x53, 0x71,
            0xEC, 0xC1, 0x59, 0x51, 0xB8, 0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D,
            0xC9, 0x04, 0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58, 0xCB,
            0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52, 0x33, 0x55, 0x7D, 0xDE,
            0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC, 0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0,
            0x83, 0xA9, 0x59, 0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
            0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D, 0x2C, 0x07, 0xE2,
            0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E, 0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D,
            0x24, 0xBD, 0xD0, 0x29, 0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9,
            0xA3, 0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D, 0xB9, 0xF2,
            0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE, 0xD7, 0xDC, 0x0E, 0xCB, 0x0A,
            0x8E, 0x68, 0xA2, 0xFF, 0x12, 0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16,
            0x4B, 0x11, 0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6, 0x26,
            0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98, 0xDB, 0x2F, 0x35, 0xD3,
            0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36, 0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C,
            0xA4, 0xC3, 0xDD, 0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
            };




        static void Main(string[] args)
        {

            Console.WriteLine("██████╗░███████╗███████╗███████╗███╗░░██╗██████╗░███████╗██████╗░");
            Console.WriteLine("██╔══██╗██╔════╝██╔════╝██╔════╝████╗░██║██╔══██╗██╔════╝██╔══██╗");
            Console.WriteLine("██║░░██║█████╗░░█████╗░░█████╗░░██╔██╗██║██║░░██║█████╗░░██████╔╝");
            Console.WriteLine("██║░░██║██╔══╝░░██╔══╝░░██╔══╝░░██║╚████║██║░░██║██╔══╝░░██╔══██╗");
            Console.WriteLine("██████╔╝███████╗██║░░░░░███████╗██║░╚███║██████╔╝███████╗██║░░██║");
            Console.WriteLine("╚═════╝░╚══════╝╚═╝░░░░░╚══════╝╚═╝░░╚══╝╚═════╝░╚══════╝╚═╝░░╚═╝");

            Console.WriteLine("███████╗██╗░░░██╗██╗██████╗░███████╗███╗░░██╗░█████╗░███████╗");
            Console.WriteLine("██╔════╝██║░░░██║██║██╔══██╗██╔════╝████╗░██║██╔══██╗██╔════╝");
            Console.WriteLine("█████╗░░╚██╗░██╔╝██║██║░░██║█████╗░░██╔██╗██║██║░░╚═╝█████╗░░");
            Console.WriteLine("██╔══╝░░░╚████╔╝░██║██║░░██║██╔══╝░░██║╚████║██║░░██╗██╔══╝░░");
            Console.WriteLine("███████╗░░╚██╔╝░░██║██████╔╝███████╗██║░╚███║╚█████╔╝███████╗");
            Console.WriteLine("╚══════╝░░░╚═╝░░░╚═╝╚═════╝░╚══════╝╚═╝░░╚══╝░╚════╝░╚══════╝");

            Console.WriteLine("██╗███╗░░██╗░██████╗██████╗░███████╗░█████╗░████████╗░█████╗░██████╗░");
            Console.WriteLine("██║████╗░██║██╔════╝██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗");
            Console.WriteLine("██║██╔██╗██║╚█████╗░██████╔╝█████╗░░██║░░╚═╝░░░██║░░░██║░░██║██████╔╝");
            Console.WriteLine("██║██║╚████║░╚═══██╗██╔═══╝░██╔══╝░░██║░░██╗░░░██║░░░██║░░██║██╔══██╗");
            Console.WriteLine("██║██║░╚███║██████╔╝██║░░░░░███████╗╚█████╔╝░░░██║░░░╚█████╔╝██║░░██║");
            Console.WriteLine("╚═╝╚═╝░░╚══╝╚═════╝░╚═╝░░░░░╚══════╝░╚════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝");
            Console.WriteLine("By Anton Kuznetsov a.k.a AntoyN0p");
            Console.WriteLine("Personal Blog > https://antonyn0p.github.io/");
            Console.WriteLine("Git > https://github.com/AntonyN0P");
            Console.WriteLine("Telegram > https://t.me/RussianF0rensics");

            List<QuarantineEntryResource> ParsedQuarantineEntryResources = new List<QuarantineEntryResource>();

            // Args parse
            var arguments = ArgParser(args);

            // Default Windows Defender Path
            string PData;
            string DefaultDefenderEntriesDir = "";
            string DefaultDefenderQuarantineDataDir = "";

            if (!(IsAdministrator()) && arguments.ContainsKey("--default"))
            {
                Console.WriteLine();
                Console.WriteLine("Program with default (--default) mode requires Admins privileges. Please start as administrator or specify another path with options --edir/--rdatadir");
                Environment.Exit(0);
            }
            else
            {
                PData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                DefaultDefenderEntriesDir = $@"{PData}\Microsoft\Windows Defender\Quarantine\Entries";
                DefaultDefenderQuarantineDataDir = $@"{PData}\Microsoft\Windows Defender\Quarantine\ResourceData";
            }

            string DefaultPathForMaliciousFileRecover = Directory.GetCurrentDirectory();



            // check args
            if (arguments.Count == 0 || arguments.ContainsKey("--help"))
            {
                PrintHelp();
                return;
            }

            // get args or set default args
            string EntriesDirectory = arguments.TryGetValue("--edir", out string EntriesDirectoryArg)
                ? EntriesDirectoryArg
                : DefaultDefenderEntriesDir;

            string DefenderQuarantineDataDirectory = arguments.TryGetValue("--rdatadir", out string ResourceDataDirArg)
                ? ResourceDataDirArg
                : DefaultDefenderQuarantineDataDir;

            string MaliciousFileRecoverDirectory = arguments.TryGetValue("--outdir", out string RecoveryDirectoryPath)
                ? RecoveryDirectoryPath
                : DefaultPathForMaliciousFileRecover;

            string TargetEncryptedQuarantineFile = arguments.TryGetValue("--targetdecrypt", out string TargetFileToDecrypt)
                ? TargetFileToDecrypt
                : null;

            // Проверка на ключ --targetdecrypt, если нужно расшифровать один файл
            if (TargetEncryptedQuarantineFile != null && arguments.ContainsKey("--targetdecrypt"))
            {
                if (File.Exists(TargetEncryptedQuarantineFile))
                {
                    try
                    {
                        byte[] DecryptedMaliciousFile = RC4Encrypt(File.ReadAllBytes(TargetEncryptedQuarantineFile));

                        //File.WriteAllBytes(DefaultPathForMaliciousFileRecover, DecryptedMaliciousFile.Skip(204).ToArray());

                        var FileSign = Encoding.UTF8.GetString(DecryptedMaliciousFile.Skip(204).Take(2).ToArray());
                        string recoveredPath = Path.Combine(MaliciousFileRecoverDirectory, Path.GetFileName(TargetEncryptedQuarantineFile));
                        if (FileSign == "PK") {
                            File.WriteAllBytes(recoveredPath + ".zip", DecryptedMaliciousFile.Skip(204).ToArray());
                            Console.WriteLine($"Malicious file {Path.GetFileName(TargetEncryptedQuarantineFile)} successfully decrypted and saved to {recoveredPath} as zip (by PK signature, but it can be Office document)");
                        }else if(FileSign == "MZ")
                        {
                            File.WriteAllBytes(recoveredPath + ".exe", DecryptedMaliciousFile.Skip(204).ToArray());
                            Console.WriteLine($"Malicious file {Path.GetFileName(TargetEncryptedQuarantineFile)} successfully decrypted and saved to {recoveredPath} as portable executable (by MZ signature)");
                        }
                        else {
                            //Check if file was moved in quarantine in COFF format (has IMAGELOAD header)
                            if ((Encoding.Unicode.GetString(DecryptedMaliciousFile.Skip(232).Take(18).ToArray()) == "IMAGELOAD") && (Encoding.UTF8.GetString(DecryptedMaliciousFile.Skip(280).Take(2).ToArray()) == "MZ"))
                            {
                                File.WriteAllBytes(recoveredPath + ".exe", DecryptedMaliciousFile.Skip(280).ToArray());
                                Console.WriteLine($"Malicious file {Path.GetFileName(TargetEncryptedQuarantineFile)} successfully decrypted and saved to {recoveredPath} as portable executable (by MZ signature)");
                            }
                            else
                            {
                                File.WriteAllBytes(recoveredPath, DecryptedMaliciousFile.Skip(204).ToArray());
                                Console.WriteLine($"Malicious file {Path.GetFileName(TargetEncryptedQuarantineFile)} successfully decrypted and saved to {recoveredPath} as Uknown, check file header manually via Hex editor");

                            }
                        }


                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error decrypting file: {ex.Message}");
                    }
                }
                else
                {
                    Console.WriteLine($"File {TargetEncryptedQuarantineFile} not found! Please check the path and try again.");
                }
                return;
            }


            // Check that EntriesDirectory exists
            if (!Directory.Exists(EntriesDirectory))
            {
                Console.WriteLine($"Cannot access {EntriesDirectory}. Please check your path and try again.");
                Environment.Exit(0);
            }

            // Read files from EntriesDirectory (from agrument or defaultDir)
            string[] FileEntries = Directory.GetFiles(EntriesDirectory);


            if (arguments.ContainsKey("--edir") && arguments.Count == 1)
            {
                //  --edir & --rdatadir
                foreach (string EntryFile in FileEntries)
                {
                    var resource = StructParser(EntryFile);
                    ParsedQuarantineEntryResources.Add(resource);
                }
                Environment.Exit(0);
            }

            if (arguments.ContainsKey("--edir") && arguments.ContainsKey("--rdatadir"))
            {
                foreach (string EntryFile in FileEntries)
                {
                    Console.WriteLine(EntryFile);
                    var resource = StructParser(EntryFile);
                    ParsedQuarantineEntryResources.Add(resource);
                }
                Console.WriteLine();
                Console.WriteLine($"Do you want to recover all quarantine files FROM: {DefenderQuarantineDataDirectory} TO: the {MaliciousFileRecoverDirectory} directory? (Y\\N)");
                var answer = Console.ReadLine();

                if (answer.ToUpper() == "Y")
                {
                    foreach (var resource in ParsedQuarantineEntryResources)
                    {
                        try
                        {
                            string[] QDataFiles = Directory.GetFiles(DefenderQuarantineDataDirectory, resource.ResourceId, SearchOption.AllDirectories);
                            if (QDataFiles.Length == 0)
                            {
                                Console.WriteLine($"File with malicious data not found for ResourceID: {resource.ResourceId}");
                                continue;
                            }

                            foreach (string QDataFile in QDataFiles)
                            {
                                byte[] DecryptedMaliciousFile = RC4Encrypt(File.ReadAllBytes(QDataFile));
                                string recoveredFilePath = Path.Combine(MaliciousFileRecoverDirectory, Path.GetFileName(resource.DetectionPath));
                                //Check if file was moved in quarantine in COFF format (has IMAGELOAD header)
                                if ((Encoding.Unicode.GetString(DecryptedMaliciousFile.Skip(232).Take(18).ToArray()) == "IMAGELOAD") && (Encoding.UTF8.GetString(DecryptedMaliciousFile.Skip(280).Take(2).ToArray()) == "MZ"))
                                {
                                    File.WriteAllBytes(recoveredFilePath, DecryptedMaliciousFile.Skip(280).ToArray());
                                    Console.WriteLine($"Malicious file {Path.GetFileName(resource.DetectionPath)} was recovered to {recoveredFilePath}");
                                    Console.WriteLine("==============================================================================================================");
                                }
                                else
                                {
                                    File.WriteAllBytes(recoveredFilePath, DecryptedMaliciousFile.Skip(204).ToArray());
                                    Console.WriteLine($"Malicious file {Path.GetFileName(resource.DetectionPath)} was recovered to {recoveredFilePath}");
                                    Console.WriteLine("==============================================================================================================");
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Error recovering file: {e.Message}");
                        }
                    }
                }
                Environment.Exit(0);
            }
            // Проверка аргумента --default для работы с привилегиями администратора
            if (arguments.ContainsKey("--default"))
            {
                if (IsAdministrator() == false)
                {
                    Console.WriteLine("Please restart the program with administrator privileges.");
                    Environment.Exit(0);
                }

                foreach (string EntryFile in FileEntries)
                {
                    var resource = StructParser(EntryFile);
                    ParsedQuarantineEntryResources.Add(resource);
                }
                Console.WriteLine();
                Console.WriteLine($"Successfully parsed {ParsedQuarantineEntryResources.Count} Quarantine Entry Resources.");
                Console.WriteLine();
                Console.WriteLine($"Do you want to try to recover all quarantine files FROM: DEFAULT Windows Defender directory {DefenderQuarantineDataDirectory} TO: the {MaliciousFileRecoverDirectory} directory? (Y\\N)");
                var answer = Console.ReadLine();

                if (answer.ToUpper() == "Y")
                {
                    foreach (var resource in ParsedQuarantineEntryResources)
                    {
                        try
                        {
                            string[] QDataFiles = Directory.GetFiles(DefenderQuarantineDataDirectory, resource.ResourceId, SearchOption.AllDirectories);
                            if (QDataFiles.Length == 0)
                            {
                                Console.WriteLine($"File with malicious data not found for ResourceID: {resource.ResourceId}");
                                continue;
                            }

                            foreach (string QDataFile in QDataFiles)
                            {
                                byte[] DecryptedMaliciousFile = RC4Encrypt(File.ReadAllBytes(QDataFile));
                                string recoveredFilePath = Path.Combine(MaliciousFileRecoverDirectory, Path.GetFileName(resource.DetectionPath));
                                //Check if file was moved in quarantine in COFF format (has IMAGELOAD header)
                                if ((Encoding.Unicode.GetString(DecryptedMaliciousFile.Skip(232).Take(18).ToArray()) == "IMAGELOAD") && (Encoding.UTF8.GetString(DecryptedMaliciousFile.Skip(280).Take(2).ToArray()) == "MZ"))
                                {
                                    File.WriteAllBytes(recoveredFilePath, DecryptedMaliciousFile.Skip(280).ToArray());
                                    Console.WriteLine($"Malicious file {Path.GetFileName(resource.DetectionPath)} was recovered to {recoveredFilePath}");
                                    Console.WriteLine("==============================================================================================================");
                                }
                                else
                                {
                                    File.WriteAllBytes(recoveredFilePath, DecryptedMaliciousFile.Skip(204).ToArray());
                                    Console.WriteLine($"Malicious file {Path.GetFileName(resource.DetectionPath)} was recovered to {recoveredFilePath}");
                                    Console.WriteLine("==============================================================================================================");
                                }
                            }
                            }
                        catch (Exception e)
                        {
                            Console.WriteLine($"Error recovering file: {e.Message}");
                        }
                    }
                }
            }
        }


        static Dictionary<string, string> ArgParser(string[] args)
        {
            var arguments = new Dictionary<string, string>();
            foreach (var arg in args)
            {
                string[] part = arg.Split('=');

                if (part.Length == 2)
                {
                    arguments[part[0]] = part[1];
                }
                else
                {
                    arguments[arg] = null;
                }
            }
            return arguments;
        }

        static void PrintHelp()
        {
            Console.WriteLine("Help:");
            Console.WriteLine("--------");
            Console.WriteLine("Usage: DefenderEvidenceInspector.exe [options]");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("   --help                        Display this message");
            Console.WriteLine("   --edir=<Path>                 Path to Quarantine entries files");
            Console.WriteLine("   --rdatadir=<Path>             Path to Quarantine ResourceData. In other words: path to encrypted maliciuos files in quarantine");
            Console.WriteLine("   --targetdecrypt=<Path>        Path to single Quarantine ResourceData for decryption. File will decrypt with the same of program directory. For specify recover directory use --outdir flag.");
            Console.WriteLine("   --outdir=<Path>               Path to directory where encrypted files would be decrypted.");
            Console.WriteLine("   --default                     Gather and parse evidencies on entire host. !!!Requires Administrator privileges!!!");

        }

        static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        public static string ReadStringUTF16(BinaryReader reader)
        {
            StringBuilder stringBuilder = new StringBuilder();

            while (true)
            {
                byte b1 = reader.ReadByte();
                byte b2 = reader.ReadByte();

                if (b1 == 0 && b2 == 0) break;

                char c = (char)(b1 | (b2 << 8));
                stringBuilder.Append(c);
            }

            return stringBuilder.ToString();
        }

        static QuarantineEntryResource StructParser(string args)
        {

            // Read the binary data from the file
            byte[] encrypted_data = File.ReadAllBytes(args);

            //Hardcoded 60 Bytes in structure
            byte[] QuarantineEntryFileHeader = encrypted_data.Take(60).ToArray();

            var offset = 0;

            // Encrypt the binary data
            byte[] decrypted_QuarantineEntryHeader = RC4Encrypt(QuarantineEntryFileHeader);

            QuarantineEntryFileHeader QfileHeader = ByteArrayToStructure<QuarantineEntryFileHeader>(decrypted_QuarantineEntryHeader, ref offset);
            Console.WriteLine("==============================================================================================================");


            //Console.WriteLine("Magic Header: " + BitConverter.ToString(QfileHeader.MagicHeader));

            byte[] QuarantineEntrySection1Size = (encrypted_data.Skip(QuarantineEntryFileHeader.Length)).Take((int)QfileHeader.Section1Size).ToArray();

            byte[] decrypted_QuarantineEntrySection1 = RC4Encrypt(QuarantineEntrySection1Size);

            QuarantineEntrySection1 QSection1 = ByteArrayToStructure<QuarantineEntrySection1>(decrypted_QuarantineEntrySection1, ref offset);

            DateTime dateTime = DateTime.FromFileTimeUtc((long)QSection1.Timestamp);
            string iso8601String = dateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            Console.WriteLine("Defender Detection TimeStamp: " + iso8601String);
            Console.WriteLine("Threat ID: " + QSection1.ThreatId);
            //Console.WriteLine("ID: " + QSection1.Id);
            //Console.WriteLine("Scan ID: " + QSection1.ScanId);

            //Get Struct len without DetectionName
            uint QuarantineEntrySection1_Size = (uint)Marshal.SizeOf(typeof(QuarantineEntrySection1));

            //Get and print only DetectionName
            byte[] detectionName = decrypted_QuarantineEntrySection1.Skip((int)QuarantineEntrySection1_Size).ToArray();
            Console.WriteLine("Threat Detection Name: " + Encoding.UTF8.GetString(detectionName));

            byte[] QuarantineEntrySection2Size = (encrypted_data.Skip(60 + (int)QfileHeader.Section1Size)).Take((int)QfileHeader.Section2Size).ToArray();

            byte[] decrypted_QuarantineEntrySection2 = RC4Encrypt(QuarantineEntrySection2Size);

            QuarantineEntrySection2_ Qsection2_ = new QuarantineEntrySection2_(decrypted_QuarantineEntrySection2);

            using (MemoryStream resourceStream = new MemoryStream(decrypted_QuarantineEntrySection2))
            using (BinaryReader reader = new BinaryReader(resourceStream))

                foreach (uint offset_ in Qsection2_.EntryOffsets)
                {
                    reader.BaseStream.Seek(offset_, SeekOrigin.Begin);
                    //Console.WriteLine($"Position after seeking to offset {offset_}: {reader.BaseStream.Position}");

                    //QuarantineEntryResource resource = new QuarantineEntryResource(reader);
                    //Resources.Add(resource);
                    string DetectionPath_ = ReadStringUTF16(reader);

                    Console.WriteLine($"Malicious file detection path: {DetectionPath_}");
                    ushort fieldCount = reader.ReadUInt16();
                    //Console.WriteLine($"Position after reading fieldCount: {reader.BaseStream.Position}");

                    string DetectionType = ReadStringUTF16(reader);
                    //Console.WriteLine($"Position after reading DetectType: {reader.BaseStream.Position}");
                    var resource = new QuarantineEntryResource(reader, fieldCount);
                    Console.WriteLine("ResourceID: " + resource.ResourceId);
                    Console.WriteLine("DetectionPath: " + resource.DetectionPath);
                    Console.WriteLine("Creation Time: " + resource.CreationTime);
                    Console.WriteLine("LastWrite Time: " + resource.LastWriteTime);
                    Console.WriteLine("LastAccess Time: " + resource.LastAccessTime);
                    return resource;
                }
            return null;

        }


        static byte[] RC4Encrypt(byte[] data)
        {
            byte[] S = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();
            int j = 0;

            // Key-Scheduling Algorithm (KSA)
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + Program.key[i % Program.key.Length]) % 256;
                Swap(S, i, j);
            }

            // Pseudo-Random Generation Algorithm (PRGA)
            byte[] result = new byte[data.Length];
            int iIndex = 0, jIndex = 0;

            for (int k = 0; k < data.Length; k++)
            {
                iIndex = (iIndex + 1) % 256;
                jIndex = (jIndex + S[iIndex]) % 256;

                Swap(S, iIndex, jIndex);

                byte keyStreamByte = S[(S[iIndex] + S[jIndex]) % 256];
                result[k] = (byte)(data[k] ^ keyStreamByte);
            }

            return result;
        }

        static void Swap(byte[] array, int i, int j)
        {
            byte temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }


        static T ByteArrayToStructure<T>(byte[] bytes, ref int offset) where T : struct
        {
            offset = 0;
            int size = Marshal.SizeOf(typeof(T));
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(bytes, offset, ptr, size);
            T obj = (T)Marshal.PtrToStructure(ptr, typeof(T));
            Marshal.FreeHGlobal(ptr);
            offset += size;
            return obj;
        }
    }
}
