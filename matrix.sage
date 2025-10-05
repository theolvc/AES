F = GF(2)
M = MatrixSpace(F,8)

L = []
while(len(L)<144):
    mat = M.random_element()
    if (mat.is_invertible()):
        L.append(mat)

def print_matrix(mat,size,file):
    file.write("{")
    for i in range(size):
        file.write("{")
        for j in range(size):
            if j != size-1:
                file.write(str(mat[i][j]))
                file.write(", ")
            else :
                file.write(str(mat[i][j]))
        if i != size-1:
            file.write("},\n")
        else :
            file.write("}\n")
    file.write("}")

L32 = []
M32 = MatrixSpace(F,32)
while(len(L32)<36):
    mat=M32.random_element()
    if(mat.is_invertible()):
        L32.append(mat)


with open("src/bijection.c","w+") as file :
    file.write("#include \"bijection.h\"\n\n")
    file.write("uint8_t Mat8[9][16][8][8] = {\n")
    for i in range(9):
        file.write("{\n")
        for j in range(16):
            print_matrix(L[16*i+j],8,file)
            file.write(",\n")
        file.write("},\n")
    file.write("};\n\n")
    file.write("uint8_t InvMat8[9][16][8][8] = {\n")
    for i in range(9):
        file.write("{\n")
        for j in range(16):
            print_matrix(L[16*i+j]^(-1),8,file)
            file.write(",\n")
        file.write("},\n")
    file.write("};\n\n")
    file.write("uint8_t Mat32[9][4][32][32] = {\n")
    for i in range(9):
        file.write("{\n")
        for j in range(4):
            print_matrix(L32[4*i+j],32,file)
            file.write(",\n")
        file.write("},\n")
    file.write("};\n\n")
    file.write("uint8_t InvMat32[9][4][32][32] = {\n")
    for i in range(9):
        file.write("{\n")
        for j in range(4):
            print_matrix(L32[4*i+j]^(-1),32,file)
            file.write(",\n")
        file.write("},\n")
    file.write("};\n\n")

    