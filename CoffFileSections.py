#!/usr/bin/env python
# -*- coding: utf-8 -*-

import io
import collections
import struct
from enum import Enum

import CoffFileSectionHeader

class CoffFileSections:
	def __init__(self,_bytes):
		self.sections_headers=[]
		self.parse_sections_headers(_bytes)
	
	def parse_sections_headers(self,_bytes):
		hstream=io.BytesIO(_bytes)
		while(True):
			Data=hstream.read(40)
			if len(Data)==0: break
			self.sections_headers.append(CoffFileSectionHeader.CoffFileSectionHeader(Data))
