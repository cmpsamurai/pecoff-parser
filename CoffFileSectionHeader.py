#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import collections
import struct
from enum import Enum


class Section_Flags(Enum):
	RESERVED_1							=0x00000000
	RESERVED_2							=0x00000001
	RESERVED_3							=0x00000002
	RESERVED_4							=0x00000004
	IMAGE_SCN_TYPE_NO_PAD				=0x00000008
	IMAGE_SCN_CNT_CODE					=0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA		=0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA	=0x00000080
	IMAGE_SCN_LNK_OTHER					=0x00000100
	IMAGE_SCN_LNK_INFO					=0x00000200
	RESERVED_6							=0x00000400
	IMAGE_SCN_LNK_REMOVE				=0x00000800
	IMAGE_SCN_LNK_COMDAT				=0x00001000
	IMAGE_SCN_GPREL						=0x00008000
	#IMAGE_SCN_MEM_PURGEABLE				=0x00020000  Reserved for future use.
	IMAGE_SCN_MEM_16BIT					=0x00020000
	IMAGE_SCN_MEM_LOCKED				=0x00040000
	IMAGE_SCN_MEM_PRELOAD				=0x00080000
	IMAGE_SCN_ALIGN_1BYTES				=0x00100000
	IMAGE_SCN_ALIGN_2BYTES				=0x00200000
	IMAGE_SCN_ALIGN_4BYTES				=0x00300000
	IMAGE_SCN_ALIGN_8BYTES				=0x00400000
	IMAGE_SCN_ALIGN_16BYTES				=0x00500000
	IMAGE_SCN_ALIGN_32BYTES				=0x00600000
	IMAGE_SCN_ALIGN_64BYTES				=0x00700000
	IMAGE_SCN_ALIGN_128BYTES			=0x00800000
	IMAGE_SCN_ALIGN_256BYTES			=0x00900000
	IMAGE_SCN_ALIGN_512BYTES			=0x00A00000
	IMAGE_SCN_ALIGN_1024BYTES			=0x00B00000
	IMAGE_SCN_ALIGN_2048BYTES			=0x00C00000
	IMAGE_SCN_ALIGN_4096BYTES			=0x00D00000
	IMAGE_SCN_ALIGN_8192BYTES			=0x00E00000
	IMAGE_SCN_LNK_NRELOC_OVFL			=0x01000000
	IMAGE_SCN_MEM_DISCARDABLE			=0x02000000
	IMAGE_SCN_MEM_NOT_CACHED			=0x04000000
	IMAGE_SCN_MEM_NOT_PAGED				=0x08000000
	IMAGE_SCN_MEM_SHARED				=0x10000000
	IMAGE_SCN_MEM_EXECUTE				=0x20000000
	IMAGE_SCN_MEM_READ					=0x40000000
	IMAGE_SCN_MEM_WRITE					=0x80000000



class CoffFileSectionHeader:
	def __init__(self,_bytes):
		self.header={}
		self.parse_section_header(_bytes)
	
	def parse_section_header(self,_bytes):
		hstream=io.BytesIO(_bytes)
		header={}
		header['Name']					=hstream.read(8)
		header['VirtualSize']			=struct.unpack('<L', hstream.read(4))[0]
		header['VirtualAddress']		=struct.unpack('<L', hstream.read(4))[0]
		header['SizeOfRawData']			=struct.unpack('<L', hstream.read(4))[0]
		header['PointerToRawData']		=struct.unpack('<L', hstream.read(4))[0]
		header['PointerToRelocations']	=struct.unpack('<L', hstream.read(4))[0]
		header['PointerToLinenumbers']	=struct.unpack('<L', hstream.read(4))[0]
		header['NumberOfRelocations']	=struct.unpack('<H', hstream.read(2))[0]
		header['NumberOfLinenumbers']	=struct.unpack('<H', hstream.read(2))[0]
		header['Characteristics']		=[]
		
		characteristics=struct.unpack('<L', hstream.read(4))[0]
		
		for i in Section_Flags:
			try:
				header["Characteristics"].append(Section_Flags(i.value&characteristics))
			except:
				pass
		self.header=header
		
