try:
	import dns.resolver
	import sys
	import logging
	import threading
	import queue
	import os
except Exception as e:
	print(">> [!] Missing Libraries")
	sys.exit()


os.system("clear")

q = queue.Queue(maxsize=0)

logging.basicConfig(filename='SubdomainTakeover_Result.txt', filemode='w')

try:
	file = input(">> [?] Enter File Containing Subdomains: ")

	read = open(file, "r").readlines()

	threads = input(">> [?] Enter Amount of Threads: ")

	def subdomain_Takeover(q):
		while True:
			subdomain = q.get()
			try:
				sub_ipv4 = dns.resolver.query(str(subdomain), "A")
				try:
					cname = dns.resolver.query(str(subdomain), "CNAME")
					for cnamee in cname:
						try:
							ipv4 = dns.resolver.query(str(cnamee), "A")
							print(">> [-] " + str(subdomain) + " Is Not Vulnerable To Subdomain Takeover")
							q.task_done()
							pass

						except Exception:
							result = (">> [+] " + str(subdomain) + " Seems Vulnerable To Subdomain Takeover With A CNAME of: " + str(cnamee))
							print(result)
							logging.critical(result + "\n")
							q.task_done()
							pass
				except Exception:
					q.task_done()
					pass
			except Exception:
				q.task_done()
				pass



except Exception as e:
	print(e)
	sys.exit()


for i in range(int(threads)):
	t = threading.Thread(target=subdomain_Takeover, args=(q,))
	t.setDaemon(True)
	t.start()


for sub in read:
	subdomain = sub.strip("\n")
	q.put(str(subdomain))


q.join()
