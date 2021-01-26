import numpy
import sys

P = Primes()
prs = []
npr = 150
for i in [0..npr]:
    prs.append(P.unrank(i))
print(prs)

@parallel(8)
def point(x):
    b_x = x;
    E=EllipticCurve(GF(p), [-3, b_x ]);
    pn = E.random_point();
    ord = pn.order();
    return (pn, ord, b_x)

b = 18958286285566608000408668544493926415504680968679321075787234672564
print(hex(b));
p = 2^224 - 2^96 + 1
E=EllipticCurve(GF(p), [-3, b ]);
print(E);

card = E.cardinality();
print(card);
#print(card.is_prime());
#print(g.order());
done = [False for i in [0..npr]]
prod = 1
psq = p*p
for (input, (pn, ord, b_x)) in point([ZZ.random_element(p-1) for i in [2..300]]):
    if(prod > psq):
        print("Have enough, parts, breaking")
	break
    #pn = out[0]
    #ord = out[1]
    print(pn);
    print(ord);
    b_x = input[0][0];

    for i, pr in enumerate(prs):
        if ord % pr == 0 and done[i] == False:
            print(done[i])
            prod *= pr
            print("Found candidate: " + str(pr) + "; can now crack up to:\n" + str(prod))
            done[i] = (pn * Integer(ord/pr), b_x)
    sys.stdout.write("\033k%s%%\033\\" % min(100, floor((50 * log(prod)) / log(p))))
    sys.stdout.flush()
print(done)

print(prod)



h = open('invalid_curves.h', 'w')
h.write("typedef struct{\n int prime;\n const char *px;\n const char *py;\n const char *b;\n} invalid_point;\n\n")
h.write("extern invalid_point invalid_points[];\n");
h.write("extern const char *curve_p;\n");
h.write("extern const char *curve_a;\n");
h.write("extern const char *curve_b;\n");
h.close()
f = open('invalid_curves.c', 'w')
f.write("#include \"invalid_curves.h\"\n\n")
f.write("const char *curve_p = \"" + hex(p) + "\";\n");
f.write("const char *curve_a = \"" + hex(p-3) + "\";\n");
f.write("const char *curve_b = \"" + hex(b) + "\";\n");
f.write("invalid_point invalid_points[] = {\n");

for idx, e in enumerate(done):
    if e != False:
        (pnt, b_x) = e
	f.write(" {" + str(prs[idx]) + ", \"" + hex(Integer(pnt[0]))
		  + "\", \"" + hex(Integer(pnt[1]))
		  + "\", \"" + hex(b_x)+"\"},\n")

f.write(" {0, 0, 0, 0}\n")
f.write("};\n")
f.close()

print("Can crack:")
print(prod)
print("of:")
print(p * p)
