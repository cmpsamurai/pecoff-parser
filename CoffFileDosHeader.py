import io
import collections
import struct
from enum import Enum

class CoffFileDosHeader:
	def __init__(self,_bytes):
		self.header=self.parse_image_dos_header(_bytes)
	
	def parse_image_dos_header(self,image_dos_header):
		hstream=io.BytesIO(image_dos_header)
		
		#header=collections.OrderedDict()
		header={}
		
		header["e_magic"]=hstream.read(2)
		header["e_cblp"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_cp"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_crlc"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_cparhdr"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_minalloc"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_maxalloc"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_ss"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_sp"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_csum"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_ip"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_cs"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_lfarlc"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_ovno"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_res"]=hstream.read(8)
		header["e_oemid"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_oeminfo"]=struct.unpack('<H',hstream.read(2))[0] 
		header["e_res2"]=hstream.read(20)
		header["e_lfanew"]=struct.unpack('<L',hstream.read(4))[0] 
		return header
