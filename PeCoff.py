#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import collections
import struct
from enum import Enum

import CoffFileDosHeader
import CoffFileHeader
import CoffFileOptionalHeader

import CoffFileSections

class PeCoff:
	def __init__(self,fname):
		self.image_dos_header=None
		self.coff_file_header=None
		self.optional_file_header=None
		self.sections_headers=[]
		self.parse_file(fname)
	
	def parse_file(self,fname):
		bfile=open(fname,"rb")
		
		self.image_dos_header=CoffFileDosHeader.CoffFileDosHeader(bfile.read(64)).header
		address_of_header=self.image_dos_header['e_lfanew']
		bfile.seek(address_of_header,0)	

		
		COFF_FILE_HEADER=bfile.read(24)
		self.coff_file_header=CoffFileHeader.CoffFileHeader(COFF_FILE_HEADER)
		
		size_of_optional_header=self.coff_file_header.header['SizeOfOptionalHeader']
		if size_of_optional_header>0:
			self.optional_file_header=CoffFileOptionalHeader.CoffFileOptionalHeader(bfile.read(size_of_optional_header))
		
		
		size_of_section_header_table=40*self.coff_file_header.header["NumberOfSections"]
		self.sections_headers=CoffFileSections.CoffFileSections(bfile.read(size_of_section_header_table)).sections_headers
