class CMD5:
	
	name = 		"cmd5"
	url = 		"http://www.cmd5.org"
	supported_algorithm = [MD5, NTLM]
	
	def isSupported (self, alg):
		"""Return True if HASHCRACK can crack this type of algorithm and
		False if it cannot."""
		
		if alg in self.supported_algorithm:
			return True
		else:
			return False


	def crack (self, hashvalue, alg):
		"""Try to crack the hash.
		@param hashvalue Hash to crack.
		@param alg Algorithm to crack."""
		
		# Check if the cracker can crack this kind of algorithm
		if not self.isSupported (alg):
			return None
		
		# Look for hidden parameters
		response = do_HTTP_request ( "http://www.cmd5.org/" )
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="[^"]*" />', html)
		viewstate = None
		if match:
			viewstate = match.group().split('"')[7]
		
		match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField1" id="ctl00_ContentPlaceHolder1_HiddenField1" value="[^"]*" />', html)
		ContentPlaceHolder1 = ""
		if match:
			ContentPlaceHolder1 = match.group().split('"')[7]
		
		match = search (r'<input type="hidden" name="ctl00.ContentPlaceHolder1.HiddenField2" id="ctl00_ContentPlaceHolder1_HiddenField2" value="[^"]*" />', html)
		ContentPlaceHolder2 = ""
		if match:
			ContentPlaceHolder2 = match.group().split('"')[7]
		
		# Build the URL
		url = "http://www.cmd5.org/"
		
		hash2 = ""
		if alg == MD5:
			hash2 = hashvalue
		else:
			if ':' in hashvalue:
				hash2 = hashvalue.split(':')[1]
		
		# Build the parameters
		params = { "__EVENTTARGET" : "",
			   "__EVENTARGUMENT" : "",
			   "__VIEWSTATE" : viewstate,
			   "ctl00$ContentPlaceHolder1$TextBoxq" : hash2,
			   "ctl00$ContentPlaceHolder1$InputHashType" : alg,
			   "ctl00$ContentPlaceHolder1$Button1" : "decrypt",
			   "ctl00$ContentPlaceHolder1$HiddenField1" : ContentPlaceHolder1,
			   "ctl00$ContentPlaceHolder1$HiddenField2" : ContentPlaceHolder2 }
			   
		header = { "Referer" : "http://www.cmd5.org/" }
		
		# Make the request
		response = do_HTTP_request ( url, params, header )
		
		# Analyze the response
		html = None
		if response:
			html = response.read()
		else:
			return None
		
		match = search (r'<span id="ctl00_ContentPlaceHolder1_LabelResult">[^<]*</span>', html)
		
		if match:
			return match.group().split('>')[1][:-6]
		else:
			return None