import json

from org.parosproxy.paros.network import HttpHeader

def is_json(s):
  flag = True
  try:
    json.loads(s)
  except ValueError:
    flag = False
  return flag

def is_multipart(head):
  c_type = str(head.getHeader(HttpHeader.CONTENT_TYPE))
  if c_type is None or c_type.__contains__('multipart/form-data') is False:
    return False
  return True

def gen_json(body_str, s):
  s += "\" id=\"form\" method=\"POST\" enctype=\"text/plain\">"
  if len(body_str) > 0:
    s += "\n<input type ='hidden' name='" + body_str[: len(body_str)] + ",\"ignore_me\":\"' value='test\"}'>"
  return s



def gen_mltpart(msg, body, s):
  s += "\" id=\"form\" enctype=\"multipart/form-data\" method=\"POST\">"
  if len(body) > 0:
    head = msg.getRequestHeader()
    c_type = str(head.getHeader(HttpHeader.CONTENT_TYPE))
    boundary = c_type[c_type.find("=") + 1 : len(c_type)]
    boundary = boundary.strip("-")
    part_body = body.split(boundary)
    part_body = list(map(lambda s:  s.strip("-"), part_body))

    names = []
    val = []
    delim = msg.getRequestHeader().getLineDelimiter()
    for i in range(1, len(part_body) - 1):
      pos_nm_start = part_body[i].find("name") + len("name=") + 1
      pos_nm_end = pos_nm_start + part_body[i][pos_nm_start : ].find("\"") 
      names.append(part_body[i][pos_nm_start : pos_nm_end])
  
      tmp = part_body[i].split(delim);
      tmp_s = ""
      j = 0
      while j < len(tmp) and len(tmp[j]) == 0:
        j+=1
      for k in range(j + 1, len(tmp[j])):
        tmp_s += tmp[j] + delim
      tmp_s = tmp_s.strip(delim)
      val.append(tmp_s)

    for i in range(len(val)):
      s += "\n<input type=\"hidden\" name=\"" + names[i] + "\" value=\"" + val[i] + "\" />"

return s

def gen_aplct(s, body):
  s += "\" id=\"form\" method=\"POST\">"
  body = body.split("&")
  for i in range(len(body)):
    key, val = body[i].split("=")
    s += "\n<input type=\"hidden\" name=\"" + key + "\" value=\"" + val + "\" >"
  return s

def invokeWith(msg):
  s = "<html>\n" + "\n<body>"
  body = msg.getRequestBody()
  if str(msg.getRequestHeader().getMethod()) == "GET":
    s += "\n<img src=\"" + str(body.getURI()) + "\">"
  elif str(msg.getRequestHeader().getMethod()) == "POST":
    body_str = str(body).strip()
    s += "\n<form action=\"" + str(msg.getRequestHeader().getURI())
    if is_json(body_str) is True:
      s = gen_json(body_str, s)
    elif is_multipart(msg.getRequestHeader()) is True:
      s = gen_mltpart(msg, body_str, s)
    else:
      s = gen_aplct(s, body_str)

    s += "\n</form>" + "\n<script>document.getElementById('form').submit();</script>"
  s += "\n</body>\n\n</html>" + "\n\n\n"
  print(s)
