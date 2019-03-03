import subprocess

def equal_until(s, t):
	for i in range(len(t)):
		if s[i] != t[i]:
			break
	return i

def rec(password, cand):
	print(password)
	for (c, h) in cand:
		cand_ = []
		for k in range(34, 127):
			out = subprocess.check_output(['./rebase', password + c + chr(k) + 'xxx'])
			out = out.split(b'\n')
			h_ = equal_until(out[1], out[2])
			if h_ > h:
				cand_.append((chr(k), h_))
		rec(password + c, cand_)

cand = []
for k in range(34, 127):
	out = subprocess.check_output(['./rebase', 'MCA{' + chr(k) + 'xxx']).split(b'\n')
	h = equal_until(out[1], out[2])
	cand.append((chr(k), h))

rec('MCA{', cand)
