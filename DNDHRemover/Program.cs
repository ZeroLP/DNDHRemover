using System.Runtime.InteropServices;

namespace DNDHRemover
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length != 1)
            {
                Console.WriteLine("Usage: DNDHRemover <path_to_PE_file>");
                return;
            }

            string filePath = args[0];

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"File: {filePath} does not exist.");
                return;
            }

            string fileName = Path.GetFileName(filePath);
            string fileExtension = Path.GetExtension(filePath);

            if (string.IsNullOrEmpty(fileName) || !(fileExtension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || fileExtension.Equals(".exe", StringComparison.OrdinalIgnoreCase)))
            {
                Console.WriteLine($"{fileName} is not a valid PE file.");
                return;
            }

            string exportToRemove = "DotNetRuntimeDebugHeader";

            byte[] peFileData;
            try
            {
                peFileData = File.ReadAllBytes(filePath);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to read file: {filePath}. Exception: {ex.Message}");
                return;
            }

            bool rmStatus = RemoveExportByName(peFileData, exportToRemove);

            if (rmStatus)
            {
                string newFilePath = Path.Combine(Path.GetDirectoryName(filePath), $"{Path.GetFileNameWithoutExtension(filePath)}_DNDHRemoved{fileExtension}");

                try
                {
                    File.WriteAllBytes(newFilePath, peFileData);
                    Console.WriteLine("DotNetRuntimeDebugHeader export header removed successfully.");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to write file: {newFilePath}. Exception: {ex.Message}");
                }
            }
            else
            {
                Console.WriteLine("Failed to remove DotNetRuntimeDebugHeader export header.");
            }
        }

        private static bool RemoveExportByName(byte[] fileImageBase, string exportToRemove)
        {
            unsafe
            {
                fixed (byte* ptr = fileImageBase)
                {
                    var dosHeader = *(Int16*)(ptr);
                    if (dosHeader != IMAGE_DOS_SIGNATURE)
                    {
                        Console.WriteLine($"PE file has an invalid DOS signature.");
                        return false;
                    }

                    Console.WriteLine("Valid DOS signature found.");

                    var e_lfanewOffset = *(uint*)(ptr + 0x3C);
                    var peHeader = *(uint*)(ptr + e_lfanewOffset);
                    if (peHeader != IMAGE_NT_SIGNATURE)
                    {
                        Console.WriteLine("PE file has an invalid PE signature");
                        return false;
                    }

                    Console.WriteLine("Valid PE signature found.");

                    // The PE File Header starts immediately after the PE signature
                    var fileHeader = *(ImageFileHeader*)(ptr + e_lfanewOffset + 4);
                    Console.WriteLine("File Header read successfully.");

                    // The Optional Header follows the File Header
                    var optionalHeader = (ImageOptionalHeader64*)((ptr + e_lfanewOffset + 4) + 20);
                    Console.WriteLine($"Optional Header Magic: {optionalHeader->Magic}");

                    // Check if it's a PE32+ file
                    bool isPE32Plus = optionalHeader->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
                    if (!isPE32Plus)
                    {
                        Console.WriteLine("PE file is not PE32+ format.");
                        return false;
                    }

                    Console.WriteLine("PE32+ format confirmed.");

                    // Get the export directory RVA and size
                    var optionalHeader64 = (ImageOptionalHeader64*)optionalHeader;
                    var exportDirectoryRVA = optionalHeader64->ExportTable.VirtualAddress;
                    var exportDirectorySize = optionalHeader64->ExportTable.Size;
                    Console.WriteLine($"Export Directory RVA: {exportDirectoryRVA}, Size: {exportDirectorySize}");

                    // Convert the RVA of the export directory to a file offset
                    var exportDirectoryOffset = RvaToFileOffset(exportDirectoryRVA, fileImageBase);
                    Console.WriteLine($"Export Directory File Offset: {exportDirectoryOffset}");

                    var exportDirectory = (ImageExportDirectory*)(ptr + exportDirectoryOffset);

                    // Convert RVAs in the export directory to file offsets
                    var eatOffset = RvaToFileOffset(exportDirectory->AddressOfFunctions, fileImageBase);
                    var enptOffset = RvaToFileOffset(exportDirectory->AddressOfNames, fileImageBase);
                    var eotOffset = RvaToFileOffset(exportDirectory->AddressOfNameOrdinals, fileImageBase);
                    Console.WriteLine($"EAT, ENPT, EOT offsets: {eatOffset}, {enptOffset}, {eotOffset}");

                    bool exportFound = false;
                    // Iterate over the export names to find the one to remove
                    for (uint i = 0; i < exportDirectory->NumberOfNames; i++)
                    {
                        uint nameRva = *((uint*)(ptr + enptOffset) + i);
                        var nameOffset = RvaToFileOffset(nameRva, fileImageBase);
                        string name = Marshal.PtrToStringAnsi((IntPtr)(ptr + nameOffset));

                        Console.WriteLine($"Inspecting export: {name}");

                        if (name == exportToRemove)
                        {
                            Console.WriteLine($"Export to remove found: {name}");
                            exportFound = true;

                            // Remove the entry from the Export Name Pointer Table (ENPT)
                            ShiftTableEntries((uint*)(ptr + enptOffset), exportDirectory->NumberOfNames, i);

                            // Find the corresponding ordinal
                            ushort ordinal = *((ushort*)(ptr + eotOffset) + i);
                            // Remove the entry from the Export Ordinal Table (EOT)
                            ShiftTableEntries((ushort*)(ptr + eotOffset), exportDirectory->NumberOfNames, i);

                            // Remove the entry from the Export Address Table (EAT)
                            ShiftTableEntries((uint*)(ptr + eatOffset), exportDirectory->NumberOfFunctions, ordinal);

                            // Update counters in the export directory
                            exportDirectory->NumberOfNames--;
                            exportDirectory->NumberOfFunctions--;

                            break;
                        }
                    }

                    if (!exportFound)
                    {
                        Console.WriteLine($"Export '{exportToRemove}' not found.");
                    }

                    return exportFound;
                }
            }
        }

        private unsafe static void ShiftTableEntries<T>(T* table, uint count, uint indexToRemove) where T : unmanaged
        {
            for (uint i = indexToRemove; i < count - 1; i++)
            {
                table[i] = table[i + 1];
            }
        }

        private static uint RvaToFileOffset(uint rva, byte[] fileImageBase)
        {
            unsafe
            {
                fixed (byte* ptr = fileImageBase)
                {
                    var e_lfanew = *(uint*)(ptr + 0x3C);
                    var fileHeader = (ImageFileHeader*)(ptr + e_lfanew + 4);
                    var sectionHeaders = (ImageSectionHeader*)(ptr + e_lfanew + 4 + sizeof(ImageFileHeader) + fileHeader->SizeOfOptionalHeader);

                    for (int i = 0; i < fileHeader->NumberOfSections; i++)
                    {
                        var section = sectionHeaders[i];
                        if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData)
                        {
                            return rva - section.VirtualAddress + section.PointerToRawData;
                        }
                    }
                }
            }
            return 0; // RVA not found in any section
        }

        // Constants for PE file format
        const int IMAGE_DOS_SIGNATURE = 0x5A4D;      // MZ
        const int IMAGE_NT_SIGNATURE = 0x00004550;   // PE00
        const int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
        const ushort IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
        const ushort IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;

        [StructLayout(LayoutKind.Sequential)]
        public struct ImageExportDirectory
        {
            public uint Characteristics;
            public uint TimeDateStamp;
            public ushort MajorVersion;
            public ushort MinorVersion;
            public uint Name;
            public uint Base;
            public uint NumberOfFunctions;
            public uint NumberOfNames;
            public uint AddressOfFunctions;     // EAT
            public uint AddressOfNames;         // ENPT
            public uint AddressOfNameOrdinals;  // EOT
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ImageFileHeader
        {
            public ushort Machine;
            public ushort NumberOfSections;
            public uint TimeDateStamp;
            public uint PointerToSymbolTable;
            public uint NumberOfSymbols;
            public ushort SizeOfOptionalHeader;
            public ushort Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ImageOptionalHeader64
        {
            public ushort Magic;
            public byte MajorLinkerVersion;
            public byte MinorLinkerVersion;
            public uint SizeOfCode;
            public uint SizeOfInitializedData;
            public uint SizeOfUninitializedData;
            public uint AddressOfEntryPoint;
            public uint BaseOfCode;
            public ulong ImageBase;
            public uint SectionAlignment;
            public uint FileAlignment;
            public ushort MajorOperatingSystemVersion;
            public ushort MinorOperatingSystemVersion;
            public ushort MajorImageVersion;
            public ushort MinorImageVersion;
            public ushort MajorSubsystemVersion;
            public ushort MinorSubsystemVersion;
            public uint Win32VersionValue;
            public uint SizeOfImage;
            public uint SizeOfHeaders;
            public uint CheckSum;
            public ushort Subsystem;
            public ushort DllCharacteristics;
            public ulong SizeOfStackReserve;
            public ulong SizeOfStackCommit;
            public ulong SizeOfHeapReserve;
            public ulong SizeOfHeapCommit;
            public uint LoaderFlags;
            public uint NumberOfRvaAndSizes;

            public ImageDataDirectory ExportTable;
            public ImageDataDirectory ImportTable;
            public ImageDataDirectory ResourceTable;
            public ImageDataDirectory ExceptionTable;
            public ImageDataDirectory CertificateTable;
            public ImageDataDirectory BaseRelocationTable;
            public ImageDataDirectory Debug;
            public ImageDataDirectory Architecture;
            public ImageDataDirectory GlobalPtr;
            public ImageDataDirectory TLSTable;
            public ImageDataDirectory LoadConfigTable;
            public ImageDataDirectory BoundImport;
            public ImageDataDirectory IAT;
            public ImageDataDirectory DelayImportDescriptor;
            public ImageDataDirectory CLRRuntimeHeader;
            public ImageDataDirectory Reserved;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ImageDataDirectory
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ImageSectionHeader
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] Name;
            public uint VirtualSize;
            public uint VirtualAddress;
            public uint SizeOfRawData;
            public uint PointerToRawData;
            public uint PointerToRelocations;
            public uint PointerToLinenumbers;
            public ushort NumberOfRelocations;
            public ushort NumberOfLinenumbers;
            public uint Characteristics;
        }
    }
}
