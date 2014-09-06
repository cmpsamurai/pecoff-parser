#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import collections
import struct
from enum import Enum


class PE_Format(Enum):
	PE32=0x10b
	PE32_PLUS=0x20b
	
class WINDOWS_SUBSYSTEM(Enum):
	IMAGE_SUBSYSTEM_UNKNOWN						=	0
	IMAGE_SUBSYSTEM_NATIVE						=	1
	IMAGE_SUBSYSTEM_WINDOWS_GUI					=	2
	IMAGE_SUBSYSTEM_WINDOWS_CUI					=	3
	IMAGE_SUBSYSTEM_POSIX_CUI					=	8
	IMAGE_SUBSYSTEM_WINDOWS_CE_GUI				=	9
	IMAGE_SUBSYSTEM_EFI_APPLICATION				=	10
	IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER		=	11
	IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER			=	12
	IMAGE_SUBSYSTEM_EFI_ROM						=	13
	IMAGE_SUBSYSTEM_XBOX						=	14

class DLL_CHARACTERISTICS(Enum):
	RESERVED_5											=	0x1000
	RESERVED_1											=	0x0001
	RESERVED_2											=	0x0002
	RESERVED_3											=	0x0004
	RESERVED_4											=	0x0008
	IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE				=	0x0040
	IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY			=	0x0080
	IMAGE_DLL_CHARACTERISTICS_NX_COMPAT					=	0x0100
	IMAGE_DLLCHARACTERISTICS_NO_ISOLATION				=	0x0200
	IMAGE_DLLCHARACTERISTICS_NO_SEH						=	0x0400 
	IMAGE_DLLCHARACTERISTICS_NO_BIND					=	0x0800
	IMAGE_DLLCHARACTERISTICS_WDM_DRIVER					=	0x2000
	IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE		=	0x8000

	
class CoffFileOptionalHeader:
	def __init__(self,stream):
		self.header={}
		self.image_format=None
		self.parse_optional_header(stream)
	
	def parse_data_directories(self,_bytes):
		directories=[]
		hstream = io.BytesIO(_bytes)
		while(True):
			data=hstream.read(8)
			if(len(data)==0): break
			entry=io.BytesIO(data)
			record={}
			record[struct.unpack('<L', entry.read(4))[0]]=struct.unpack('<L', entry.read(4))[0]
			directories.append(record)
		self.header['IMAGE_DATA_DIRECTORIES']=directories
				
	def parse_standard_fields(self,_bytes):
		header={}
		hstream = io.BytesIO(_bytes)
		header['MajorLinkerVersion']		=	struct.unpack('<B', hstream.read(1))[0]
		header['MinorLinkerVersion']		=	struct.unpack('<B', hstream.read(1))[0]
		header['SizeOfCode']				=	struct.unpack('<L', hstream.read(4))[0]
		header['SizeOfInitializedData']		=	struct.unpack('<L', hstream.read(4))[0]
		header['SizeOfUninitializedData']	=	struct.unpack('<L', hstream.read(4))[0]
		header['AddressOfEntryPoint']		=	struct.unpack('<L', hstream.read(4))[0]
		header['BaseOfCode']				=	struct.unpack('<L', hstream.read(4))[0]
		if self.image_format==PE_Format.PE32:
			header['BaseOfData']=	struct.unpack('<L', hstream.read(4))[0]
		
		self.header['STANDARD_FIELDS']=header
	
	def parse_windows_specific_fields(self,_bytes):
		header={}
		hstream=io.BytesIO(_bytes)
		
		if self.image_format == PE_Format.PE32:
			header['ImageBase']		=	struct.unpack('<L', hstream.read(4))[0]
		elif self.image_format == PE_Format.PE32_PLUS:
			header['ImageBase']		=	struct.unpack('<Q', hstream.read(8))[0]
		
		header['SectionAlignment']				=	struct.unpack('<L', hstream.read(4))[0]
		header['FileAlignment']					=	struct.unpack('<L', hstream.read(4))[0]
		header['MajorOperatingSystemVersion']	=	struct.unpack('<H', hstream.read(2))[0]
		header['MinorOperatingSystemVersion']	=	struct.unpack('<H', hstream.read(2))[0]
		header['MajorImageVersion']				=	struct.unpack('<H', hstream.read(2))[0]
		header['MinorImageVersion']				=	struct.unpack('<H', hstream.read(2))[0]
		header['MajorSubsystemVersion']				=	struct.unpack('<H', hstream.read(2))[0]
		header['MinorSubsystemVersion']				=	struct.unpack('<H', hstream.read(2))[0]
		header['Win32VersionValue']					=	struct.unpack('<L', hstream.read(4))[0]
		header['SizeOfImage']						=	struct.unpack('<L', hstream.read(4))[0]
		header['SizeOfHeaders']						=	struct.unpack('<L', hstream.read(4))[0]
		header['CheckSum']							=	struct.unpack('<L', hstream.read(4))[0]
		header['Subsystem']							=	WINDOWS_SUBSYSTEM(struct.unpack('<H', hstream.read(2))[0])
		header['DllCharacteristics']				=	DLL_CHARACTERISTICS(struct.unpack('<H', hstream.read(2))[0])
		
		if self.image_format == PE_Format.PE32:
			header['SizeOfStackReserve']		=	struct.unpack('<L', hstream.read(4))[0]
			header['SizeOfStackCommit']			=	struct.unpack('<L', hstream.read(4))[0]
			header['SizeOfHeapReserve']			=	struct.unpack('<L', hstream.read(4))[0]
			header['SizeOfHeapCommit']			=	struct.unpack('<L', hstream.read(4))[0]
		elif self.image_format == PE_Format.PE32_PLUS:
			header['SizeOfStackReserve']		=	struct.unpack('<Q', hstream.read(8))[0]
			header['SizeOfStackCommit']			=	struct.unpack('<Q', hstream.read(8))[0]
			header['SizeOfHeapReserve']			=	struct.unpack('<Q', hstream.read(8))[0]
			header['SizeOfHeapCommit']			=	struct.unpack('<Q', hstream.read(8))[0]
			
		header['LoaderFlags']						=	struct.unpack('<L', hstream.read(4))[0]
		header['NumberOfRvaAndSizes']						=	struct.unpack('<L', hstream.read(4))[0]
		
		self.header['WINDOWS_SPECIFIC_FIELDS']=header
		
	def parse_optional_header(self,coff_file_optional_header):	
		hstream=io.BytesIO(coff_file_optional_header)
		
		self.image_format=PE_Format(struct.unpack('<H', hstream.read(2))[0])
		
		# PE32 File
		if self.image_format == PE_Format.PE32:
			self.parse_standard_fields(hstream.read(26))
			self.parse_windows_specific_fields(hstream.read(68))
		elif self.image_format==PE_FORMAT.PE32_PLUS:
			self.parse_standard_fields(hstream.read(22))
			self.parse_windows_specific_fields(hstream.read(88))
		
		self.parse_data_directories(hstream.read())
