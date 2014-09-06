#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import collections
import struct
from enum import Enum

class ImageFileType(Enum):
	IMAGE_DOS_SIGNATURE = 0x5A4D # MZ
	IMAGE_OS2_SIGNATURE = 0x454E # NE
	IMAGE_OS2_SIGNATURE_LE =0x454C # LE
	IMAGE_NT_SIGNATURE= 0x00004550 # PE00
	
	
class Machine_Types(Enum):
	IMAGE_FILE_MACHINE_UNKNOWN		= 0x0		# The contents of this field are assumed to be applicable to any machine type
	IMAGE_FILE_MACHINE_AM33			= 0x1d3		# Matsushita AM33
	IMAGE_FILE_MACHINE_AMD64		= 0x8664	# x64
	IMAGE_FILE_MACHINE_ARM			= 0x1c0		# ARM little endian
	IMAGE_FILE_MACHINE_ARMNT		= 0x1c4		# ARMv7 (or higher) Thumb mode only
	IMAGE_FILE_MACHINE_ARM64		= 0xaa64	# ARMv8 in 64-bit mode
	IMAGE_FILE_MACHINE_EBC			= 0xebc		# EFI byte code
	IMAGE_FILE_MACHINE_I386			= 0x14c		# Intel 386 or later processors and compatible processors
	IMAGE_FILE_MACHINE_IA64			= 0x200		# Intel Itanium processor family
	IMAGE_FILE_MACHINE_M32R			= 0x9041	# Mitsubishi M32R little endian
	IMAGE_FILE_MACHINE_MIPS16		= 0x266		# MIPS16
	IMAGE_FILE_MACHINE_MIPSFPU		= 0x366		# MIPS with FPU
	IMAGE_FILE_MACHINE_MIPSFPU16 	= 0x466		# MIPS16 with FPU
	IMAGE_FILE_MACHINE_POWERPC 		= 0x1f0		# Power PC little endian
	IMAGE_FILE_MACHINE_POWERPCFP 	= 0x1f1 	# Power PC with floating point support
	IMAGE_FILE_MACHINE_R4000 		= 0x166     # MIPS little endian
	IMAGE_FILE_MACHINE_SH3 			= 0x1a2		# Hitachi SH3
	IMAGE_FILE_MACHINE_SH3DSP 		= 0x1a3		# Hitachi SH3 DSP
	IMAGE_FILE_MACHINE_SH4 			= 0x1a6		# Hitachi SH4
	IMAGE_FILE_MACHINE_SH5 			= 0x1a8		# Hitachi SH5
	IMAGE_FILE_MACHINE_THUMB 		= 0x1c2		# ARM or Thumb (“interworking”)
	IMAGE_FILE_MACHINE_WCEMIPSV2 	= 0x169		# MIPS little-endian WCE v2
	
	



class FILE_CHARACTERISITCS(Enum):
	IMAGE_FILE_RELOCS_STRIPPED 			=	0x0001
	IMAGE_FILE_EXECUTABLE_IMAGE 		=   0x0002
	IMAGE_FILE_LINE_NUMS_STRIPPED 		= 	0x0004
	IMAGE_FILE_LOCAL_SYMS_STRIPPED		=	0x0008
	IMAGE_FILE_AGGRESSIVE_WS_TRIM		=	0x0010
	IMAGE_FILE_LARGE_ADDRESS_AWARE		=	0x0020
	FUTURE_USE_RESERVERD				=	0x0040
	IMAGE_FILE_BYTES_REVERSED_LO		=	0x0080
	IMAGE_FILE_32BIT_MACHINE			=	0x0100
	IMAGE_FILE_DEBUG_STRIPPED			=	0x0200
	IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	=	0x0400
	IMAGE_FILE_NET_RUN_FROM_SWAP		=	0x0800
	IMAGE_FILE_SYSTEM					=	0x1000
	IMAGE_FILE_DLL						=	0x2000
	IMAGE_FILE_UP_SYSTEM_ONLY			=	0x4000
	IMAGE_FILE_BYTES_REVERSED_HI		=	0x8000
	

class CoffFileHeader:
	def __init__(self,_bytes):
		self.signature=None
		self.header=self.parse_header(_bytes)
		
	def parse_header(self,coff_file_header):
		header={}
		hstream=io.BytesIO(coff_file_header)
		
		self.signature=ImageFileType(struct.unpack('i', hstream.read(4))[0])
		
		header["Machine"]=Machine_Types(struct.unpack('<H', hstream.read(2))[0] )
		header["NumberOfSections"]=struct.unpack('<H',hstream.read(2))[0] 
		header["TimeDateStamp"]=struct.unpack('<L',hstream.read(4))[0]  
		header["PointerToSymbolTable"]=struct.unpack('<L',hstream.read(4))[0]  
		header["NumberOfSymbols"]=struct.unpack('<L',hstream.read(4))[0]  
		header["SizeOfOptionalHeader"]=struct.unpack('<H', hstream.read(2))[0]
		header["Characteristics"]=[]
		characteristics=struct.unpack('<H', hstream.read(2))[0]
		for i in FILE_CHARACTERISITCS:
			try:
				header["Characteristics"].append(FILE_CHARACTERISITCS(i.value&characteristics))
			except:
				pass
			
		return header
