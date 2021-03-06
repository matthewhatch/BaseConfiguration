# Localized	09/27/2013 04:07 AM (GMT)	303:4.80.0411 	ArchiveProvider.psd1
# Localized ArchiveProvider.psd1

ConvertFrom-StringData @'
###PSLOC
InvalidChecksumArgsMessage=Specifying a Checksum without requesting content validation (the Validate parameter) is not meaningful
InvalidDestinationDirectory=The specified destination directory {0} does not exist or is not a directory
InvalidSourcePath=The specified source file {0} does not exist or is not a file
ErrorOpeningExistingFile=An error occurred while opening the file {0} on disk. Please examine the inner exception for details
ErrorOpeningArchiveFile=An error occurred while opening the archive file {0}. Please examine the inner exception for details
ItemExistsButIsWrongType=The named item ({0}) exists but is not the expected type, and Force was not specified
ItemExistsButIsIncorrect=The destination file {0} has been determined not to match the source, but Force has not been specified. Cannot continue
ErrorCopyingToOutstream=An error was encountered while copying the archived file to {0}
PackageUninstalled=The archive at {0} was removed from destination {1}
PackageInstalled=The archive at {0} was unpacked to destination {1}
ConfigurationStarted=The configuration of MSFT_ArchiveResource is starting
ConfigurationFinished=The configuration of MSFT_ArchiveResource has completed
MakeDirectory=Make directory {0}
RemoveFileAndRecreateAsDirectory=Remove existing file {0} and replace it with a directory of the same name
RemoveFile=Remove file {0}
RemoveDirectory=Remove directory {0}
UnzipFile=Unzip archived file to {0}
DestMissingOrIncorrectTypeReason=The destination file {0} was missing or was not a file
DestHasIncorrectHashvalue=The destination file {0} exists but its checksum did not match the origin file
DestShouldNotBeThereReason=The destination file {0} exists but should not
###PSLOC

'@
