#  DNDHRemover
DNDH Remover is a tool designed for removing the DotNetRuntimeDebugHeader (DNDH) export header from NativeAOT published .NET Portable Executable (PE) files. This utility is particularly useful for .NET developers who are working with NativeAOT and require a temporary solution for managing PE files until the full support is integrated in .NET 9, as outlined in [this pull request](https://github.com/dotnet/runtime/pull/91775).

The tool is specifically targeted at `.dll` and `.exe` files, providing a straightforward and efficient means of removing the DNDH export header.

##  Usage
To use DNDH Remover, follow these steps:
 1. Open a command prompt or terminal.
 2. Navigate to the directory containing the DNDH Remover executable.
 3. Run the tool with the path to the PE file:

    DNDHRemover.exe <path_to_PE_file>

## Before Removing
![](https://github.com/ZeroLP/DNDHRemover/blob/main/Before.JPG)

## After Removing
![](https://github.com/ZeroLP/DNDHRemover/blob/main/After.JPG)
