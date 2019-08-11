#!/usr/bin/python

import json, sys, getopt, os,math
def usage():
  print("Usage: %s --file=[filename]" % sys.argv[0])
  sys.exit()

def main(argv):
  
  file=''
 
  myopts, args = getopt.getopt(sys.argv[1:], "", ["file="])
 
  for o, a in myopts:
    if o in ('-f, --file'):
      file=a
    else:
      usage()

  if len(file) == 0:
    usage()
 
  corpus = open(file)
  f = open("results.txt", "a")
  urldata = json.load(corpus)

  # Young domains are likely MORE malicious than old domains
  # Domains which don't return IP addresses could be fast-flux domains. These domains are likely to be MORE malicious. For example, how often does a DNS query for google.com fail?
  # URLs which are listed in the Alexa top 1,000,000 are LIKELY to be LESS malicious than those that are not.
  # URLs with a very low Alexa rank are likely to be LESS malicious that those with a high Alexa rank. This is known as "URL Prevalence"
  # Another hint: 50% of the URLs in each file are malicious. Use this to help validate your results.
  # What about file extension. How often do you *really* download raw .exe file directly from the web, instead of a software package.
  # What about query string?
  malCount = 0
  cleanCount = 0
  for record in urldata:
    totalRisk = 0
    ageRisk  = 0
    fluxRisk = 0
    alexaRisk = 0
    fileTypeRisk = 0
    tldRisk = 0
    # exponential decay on age risk
    oneMinusB = .99
    
    ageRisk = math.pow( oneMinusB, int(record["domain_age_days"])) * 10
    if record["ips"] is None:
      fluxRisk = 3
    if record["alexa_rank"] is None:
      record["alexa_rank"] = 2000000
    alexaRisk = math.pow( oneMinusB, int(record["alexa_rank"])) * 4.5
    if ".exe" in record["url"]:
      fileTypeRisk = 4
    if record["tld"] is not "com":
      tldRisk = 1
    if record["port"] is not (80 or "80"):
      totalRisk += 1

    totalRisk += ageRisk + fluxRisk + alexaRisk + fileTypeRisk + tldRisk
    
    if totalRisk > 5:
      record["malicious_url"] = 1
      malCount +=1
    else:
      record["malicious_url"] = 0
      cleanCount +=1 
    f.write(str(record["malicious_url"]))
      
  print "Malicious Urls: ", malCount, "Clean Urls: ", cleanCount
  corpus.close()
  f.close()

if __name__ == "__main__":
  main(sys.argv[1:])
