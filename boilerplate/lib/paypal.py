#Service Layer API for the Paypal Adaptive payments
import urllib, urllib2
import logging
import simplejson as json
log = logging.getLogger(__name__)
class PaypalAdaptivePayment(object):
	"""
	Paypal Object to initialize and conducting the payments
	"""
	def __init__(self, paypal_sandbox_enabled):
		"""Constructor for the Paypal Api Sets the headers and api credentials which are required for the initialization of the payments
		"""
		assert paypal_sandbox_enabled, "missing arguments..."
		self.request_data_format = 'JSON'
		self.response_data_format = 'JSON'
		self.paypal_sandbox_enabled = paypal_sandbox_enabled
		if paypal_sandbox_enabled:
			self.paypal_secure_user_id = "alexsm_1352179260_biz_api1.gmail.com"
			self.paypal_secure_password = "1352179287"
			self.paypal_api_signature = "AFcWxV21C7fd0v3bYYYRCpSSRl31AzzgIWZ2ho59zLjdU9Y9TeYyx4.i"
			self.receiver_email = "alexsm_1352179260_biz@gmail.com"
			self.request_url =  "https://svcs.sandbox.paypal.com/AdaptivePayments/Pay"
		else:
			self.paypal_secure_user_id = "your live paypal secure user id"
			self.paypal_secure_password = "your live secure password"
			self.paypal_api_signature = "Your live ApI signature"
			self.receiver_email = "Your Live Receiver Email"
			self.request_url =  "https://paypal.com/AdaptivePayments/Pay"

	def check_payment_status(self, paykey):
		#try:
		header_data = {}
		header_data["X-PAYPAL-SERVICE-VERSION"]= "1.0.0"
		header_data["X-PAYPAL-SECURITY-USERID"] = self.paypal_secure_user_id
		header_data["X-PAYPAL-SECURITY-PASSWORD"] = self.paypal_secure_password
		header_data["X-PAYPAL-SECURITY-SIGNATURE"] = self.paypal_api_signature
		header_data["X-PAYPAL-REQUEST-DATA-FORMAT"] = self.request_data_format
		header_data["X-PAYPAL-RESPONSE-DATA-FORMAT"] = self.response_data_format
		if self.paypal_sandbox_enabled:
			header_data["X-PAYPAL-APPLICATION-ID"] = "APP-80W284485P519543T"
			request_url =  "https://svcs.sandbox.paypal.com/AdaptivePayments/PaymentDetails"
		else:
			header_data["X-PAYPAL-APPLICATION-ID"] = "Your Live Paypal Application ID"
			request_url =  "https://paypal.com/AdaptivePayments/PaymentDetails"
		logging.info('paykey verificacion: %s'% paykey)
		params = {'payKey':str(paykey),  'requestEnvelope':{ 'errorLanguage':'en_US'}}
		paypal_request_data = json.dumps(params)
		logging.info('paypal_request_data %s' % paypal_request_data)
		logging.info('where1')
		logging.info('%s %s %s ' % (request_url,paypal_request_data,header_data))
		req = urllib2.Request(request_url,paypal_request_data,header_data)
		logging.info('where2')
		response = urllib2.urlopen(req)
		logging.info('where3')
		stresponse=str(response.read())
		logging.info('where4 %s' % stresponse)
		return json.loads(stresponse)
		#except:
		#	log.exception("Unable to initialize the payment flow...")

	def initialize_payment(self,amount,cancel_url,return_url):
		try:
			header_data = {}
			header_data["X-PAYPAL-SECURITY-USERID"] = self.paypal_secure_user_id
			header_data["X-PAYPAL-SECURITY-PASSWORD"] = self.paypal_secure_password
			header_data["X-PAYPAL-SECURITY-SIGNATURE"] = self.paypal_api_signature
			header_data["X-PAYPAL-REQUEST-DATA-FORMAT"] = self.request_data_format
			header_data["X-PAYPAL-RESPONSE-DATA-FORMAT"] = self.response_data_format
			if self.paypal_sandbox_enabled:
				header_data["X-PAYPAL-APPLICATION-ID"] = "APP-80W284485P519543T"
			else:
				header_data["X-PAYPAL-APPLICATION-ID"] = "Your Live Paypal Application ID"
			params = {'actionType':'PAY', 'receiverList':{'receiver':[{'email':self.receiver_email,'amount':amount}]}, 'cancelUrl':cancel_url, 'requestEnvelope':{ 'errorLanguage':'en_US'}, 'currencyCode':'MXN', 'returnUrl':return_url}
			paypal_request_data = json.dumps(params)
			req = urllib2.Request(self.request_url,paypal_request_data,header_data)
			response = urllib2.urlopen(req)
			return json.loads(response.read())
		except:
			log.exception("Unable to initialize the payment flow...")