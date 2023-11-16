using System.Runtime.InteropServices;

namespace DNDHRemover;

public unsafe class Program
{
    static void Main(string[] args)
    {
        InternalMain(args);
        Console.ReadLine();
    }

    static void InternalMain(string[] args)
    {
        if (args.Length != 1)
        {
            Console.WriteLine("Usage: DNDHRemover <path_to_PE_file>");
            return;
        }

        var filePath = args[0];

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"File: {filePath} does not exist.");
            return;
        }

        var fileName = Path.GetFileName(filePath);
        var fileExtension = Path.GetExtension(filePath);

        if (string.IsNullOrEmpty(fileName) || !(fileExtension.Equals(".dll", StringComparison.OrdinalIgnoreCase) || fileExtension.Equals(".exe", StringComparison.OrdinalIgnoreCase)))
        {
            Console.WriteLine($"{fileName} is not a valid PE file.");
            return;
        }

        var exportToRemove = "DotNetRuntimeDebugHeader";

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

        var rmStatus = RemoveExportByName(peFileData, exportToRemove);

        if (rmStatus)
        {
            var newFilePath = Path.Combine(Path.GetDirectoryName(filePath), $"{Path.GetFileNameWithoutExtension(filePath)}_DNDHRemoved{fileExtension}");

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

    static bool RemoveExportByName(byte[] fileImageBase, string exportToRemove)
    {
        fixed (byte* ptr = fileImageBase)
        {
            var dosHeader = *(short*)(ptr);
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
            var exportDirectoryRVA = optionalHeader->ExportTable.VirtualAddress;
            var exportDirectorySize = optionalHeader->ExportTable.Size;
            Console.WriteLine($"Export Directory RVA: {exportDirectoryRVA}, Size: {exportDirectorySize}");

            // Convert the RVA of the export directory to a file offset
            var exportDirectoryOffset = RvaToFileOffset(exportDirectoryRVA, ptr);
            Console.WriteLine($"Export Directory File Offset: {exportDirectoryOffset}");

            var exportDirectory = (ImageExportDirectory*)(ptr + exportDirectoryOffset);

            // Convert RVAs in the export directory to file offsets
            var eatOffset = RvaToFileOffset(exportDirectory->AddressOfFunctions, ptr);
            var enptOffset = RvaToFileOffset(exportDirectory->AddressOfNames, ptr);
            var eotOffset = RvaToFileOffset(exportDirectory->AddressOfNameOrdinals, ptr);
            Console.WriteLine($"EAT, ENPT, EOT offsets: {eatOffset}, {enptOffset}, {eotOffset}");

            bool exportFound = false;
            // Iterate over the export names to find the one to remove
            for (uint i = 0; i < exportDirectory->NumberOfNames; i++)
            {
                uint nameRva = *((uint*)(ptr + enptOffset) + i);
                var nameOffset = RvaToFileOffset(nameRva, ptr);
                var name = Marshal.PtrToStringAnsi((nint)(ptr + nameOffset));

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
                    ShiftOrdinalTableEntries((ushort*)(ptr + eotOffset), exportDirectory->NumberOfNames, i);

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

    static void ShiftTableEntries<T>(T* table, uint count, uint indexToRemove) where T : unmanaged
    {
        for (uint i = indexToRemove; i < count - 1; i++)
            table[i] = table[i + 1];
    }

    static void ShiftOrdinalTableEntries(ushort* table, uint count, uint indexToRemove)
    {
        for (uint i = indexToRemove; i < count - 1; i++)
            table[i] = (ushort)(table[i + 1] - 1);
    }

    static uint RvaToFileOffset(uint rva, byte* fileImageBase)
    {
        var e_lfanew = *(uint*)(fileImageBase + 0x3C);
        var fileHeader = (ImageFileHeader*)(fileImageBase + e_lfanew + 4);
        var sectionHeaders = (ImageSectionHeader*)(fileImageBase + e_lfanew + 4 + sizeof(ImageFileHeader) + fileHeader->SizeOfOptionalHeader);

        for (int i = 0; i < fileHeader->NumberOfSections; i++)
        {
            var section = sectionHeaders[i];
            if (rva >= section.VirtualAddress && rva < section.VirtualAddress + section.SizeOfRawData)
            {
                return rva - section.VirtualAddress + section.PointerToRawData;
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
    struct ImageExportDirectory
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
    struct ImageFileHeader
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
    struct ImageOptionalHeader64
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
    struct ImageDataDirectory
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct ImageSectionHeader
    {
        public fixed byte Name[8];
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