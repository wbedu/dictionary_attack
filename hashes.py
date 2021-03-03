import hashlib


def myFunc(e):
  return e["length"]



algos = [{"algo": hashlib.md5, "name": "md5"}, {"algo": hashlib.sha1, "name":"sha1"}, {"algo": hashlib.sha224, "name": "sha224"}, {"algo": hashlib.sha256, "name":"sha256"}, {"algo": hashlib.sha384, "name":"sha384"}, {"algo": hashlib.sha512, "name": "sha512"}]

res = []
for item in algos:
    item["length"] = len(item["algo"]("pim".encode('utf-8')).hexdigest())
    res.append(item)

res.sort(reverse=True, key=myFunc)




for item in ["{length}: hashlib.{name}".format(**item) for item in res]:
    print(item)
