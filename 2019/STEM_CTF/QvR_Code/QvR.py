from PIL import Image

img = Image.open('QvR.png')
x, y = img.size

bw = [(0, 0, 0, 255), (255, 255, 255, 255)]

for k in range(64):
	colors = {}
	colors[(238, 22, 31, 255)] = bw[k & 1]
	colors[(92, 41, 146, 255)] = bw[(k >> 1) & 1]
	colors[(245, 131, 26, 255)] = bw[(k >> 2) & 1]
	colors[(255, 242, 0, 255)] = bw[(k >> 3) & 1]
	colors[(0, 168, 93, 255)] = bw[(k >> 4) & 1]
	colors[(0, 102, 180, 255)] = bw[(k >> 5) & 1]
	
	img_ = Image.new('RGBA', img.size)
	for i in range(x):
		for j in range(y):
			c = img.getpixel((i, j))
			if c in bw:
				img_.putpixel((i, j), c)
			else:
				img_.putpixel((i, j), colors[c])
	
	img_.save('q/%s.png' % k)
	print('[+] Saved %s.png' % k)