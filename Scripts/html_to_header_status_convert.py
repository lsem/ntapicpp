############################################################################
# html_to_header_status_convert.py
# By lsem, 2013
# Generates
############################################################################

from HTMLParser import HTMLParser


INPUT_FILENAME = "../Manuals/StatusCodes.html"
OUTPUT_FILENAME = "../Sources/NTStatusErrors.hpp"
 

class ParserStateEnum:	
	ParsingBody = 0
	ParsingTable = 1
	ParsingRow = 2
	Error = 5


class NTStatusesTableParser(HTMLParser):
	
	def __init__(self):
		HTMLParser.__init__(self)

		self.stop = False
		self.state = ParserStateEnum.ParsingBody
		self.columns_parsed_count = None
		self.current_code = None
		self.current_name = None
		self.current_description = None
		self.results = []

	def handle_starttag(self, tag, attrs):
		if self.stop:
			return

		if tag == 'table':
			if self.state == ParserStateEnum.ParsingBody: # start of the table
				self.state = ParserStateEnum.ParsingTable
		elif tag == 'tr':
			if self.state == ParserStateEnum.ParsingTable:
				self.state = ParserStateEnum.ParsingRow
				self.columns_parsed_count = 0
		elif tag == 'td':
			if self.state != ParserStateEnum.ParsingRow:
				raise Exception("TD in inapproprite state")
					
	
	def handle_endtag(self, tag):
		if self.stop:
			return

		if tag == 'table':
			self.state = ParserStateEnum.ParsingBody
			self.stop = True
		elif tag == 'tr':
			if self.columns_parsed_count != 3:
				error ="Row has unexpected count of columns. Expected columns are (code, name, description). Actual: {0}".format(self.columns_parsed_count)
				raise Exception(error)			
			self.results.append((self.current_code, self.current_name, self.current_description))
			self.state = ParserStateEnum.ParsingTable

		elif tag == 'td':			
			self.columns_parsed_count += 1

	def handle_data(self, data):
		if self.stop:
			return

		if self.state != ParserStateEnum.ParsingRow:
			return

		if self.columns_parsed_count == 0:
			self.current_name = data
		elif self.columns_parsed_count == 1:
			self.current_code = data
		elif self.columns_parsed_count == 2:
			self.current_description = data.strip("\t\n").replace('\n', ' ').replace('\"', '\\\"')


class CppHeaderGeneratorSettings:
	def __init__(self):
		self.place_into_namespace = None
		self.use_prefix_for_enum_codes = None

class CppHeaderGenerator:
	def __init__(self, results, settings, output_file_name):
		self.results = results
		self.result_file_content = ""
		self.output_file_name = output_file_name
		self.finished = False
		self.settings = settings

	def execute(self):
		self._generate_file_header()
		self._generate_enumeration()
		self._generate_data_table()
		self._generate_decode_function()
		self._generate_file_footer()
		self.finished = True
		self._write_results()

	def _generate_file_header(self):
		self.result_file_content += "#include <string>\n"
		self.result_file_content += "\n\n";		
		if self.settings.place_into_namespace:
			self.result_file_content += "namespace WinNativeAPI\n"
			self.result_file_content += "{\n\n\n"
		self.result_file_content += "static const size_t g_tableLength = {0};\n\n".format(len(self.results))

	def _generate_decode_function(self):
		function_body = ""
		function_body += "\n\n"
		function_body += "NtStatusInfo *DecodeNtStatusInfo(NTSTATUS_CODES code)\n"
		function_body += "{    \n"
		function_body += "    for (size_t index = 0; index != g_tableLength; ++index)\n"
		function_body += "    {\n"
		function_body += "        if (g_ntSatusInfoTable[index].m_code == code)\n"
		function_body += "        {\n"
		function_body += "            return &g_ntSatusInfoTable[index];\n"
		function_body += "        }\n"
		function_body += "    }\n"
		function_body += "    return NULL;        \n"
		function_body += "}\n"
		self.result_file_content += function_body

	def _generate_file_footer(self):
		if self.settings.place_into_namespace:
			self.result_file_content += "\n\n} // namespace WinNativeAPI\n\n"

	def _generate_enumeration(self):
		self.result_file_content += "enum NTSTATUS_CODES\n"		
		self.result_file_content += "{\n"		
		
		for result in self.results:					
			enum_code_prefix = ""
			if self.settings.use_prefix_for_enum_codes:
				enum_code_prefix = "SC_"
			enum_code = enum_code_prefix + result[1]
			enum_value = result[0]			
			line = "\t{0: <35}\t= {1},\n".format(enum_code, enum_value)
			self.result_file_content += line

		self.result_file_content += "}; // enum NTSTATUS_CODES\n"
		self.result_file_content += "\n\n"

	def _generate_data_table(self):
		self.result_file_content += "struct NtStatusInfo\n"
		self.result_file_content += "{\n"
		self.result_file_content += "\tconst unsigned long m_code;\n"
		self.result_file_content += "\tconst char *m_name;\n"
		self.result_file_content += "\tconst char *m_description;\n"
		self.result_file_content += "};\n\n"

		self.result_file_content += "NtStatusInfo g_ntSatusInfoTable[] = \n"
		self.result_file_content += "{\n"
		
		for result in self.results:
			code = result[0] + ","
			name = "\"" + result[1] + "\","
			description = "\"" + result[2] + "\""
			line = "\t{{ {0: <15} {1: <35} \t{2} }},\n".format(code, name, description)
			self.result_file_content += line
		
		self.result_file_content += "}; //g_ntSatusInfoTable\n"

		pass

	def _write_results(self):
		assert(self.finished)
		with open(self.output_file_name, 'w') as out_file:
			out_file.write(self.result_file_content)


if __name__ == '__main__':
	html_file = open(INPUT_FILENAME, 'r')

	parser = NTStatusesTableParser()

	file_data = html_file.read()
	print "Size is: {0}".format(len(file_data))

	parser.feed(file_data)

	settings = CppHeaderGeneratorSettings()
	settings.place_into_namespace = True
	settings.use_prefix_for_enum_codes = True

	generator = CppHeaderGenerator(parser.results, settings, OUTPUT_FILENAME)
	generator.execute()
