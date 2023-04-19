#include <pbc.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>


#define TYPEA_PARAMS \
"type a\n" \
"q 87807107996633125224377819847540498158068831994142082" \
"1102865339926647563088022295707862517942266222142315585" \
"8769582317459277713367317481324925129998224791\n" \
"h 12016012264891146079388821366740534204802954401251311" \
"822919615131047207289359704531102844802183906537786776\n" \
"r 730750818665451621361119245571504901405976559617\n" \
"exp2 159\n" \
"exp1 107\n" \
"sign1 1\n" \
"sign0 1\n"
//把参数直接输入进来，确保每次生成群一样，不再需要命令参数

using namespace std;

int main(int argc, char** argv)
{
	pairing_t pairing;
	pairing_init_set_buf(pairing, TYPEA_PARAMS, strlen(TYPEA_PARAMS));
	if (!pairing_is_symmetric(pairing)) pbc_die("pairing must be symmetric");  //进行初始化

	int n;  //定义用户数量
	std::cout << "请输入用户数量" << std::endl;
	std::cin >> n;
	const int attri = 7;  //定义属性数量


	//系统初始化
	element_t g, a, b, c, r1, r2;  //私钥

	element_init_G1(g, pairing);

	element_init_Zr(a, pairing);
	element_init_Zr(b, pairing);
	element_init_Zr(c, pairing);
	element_init_Zr(r1, pairing);
	element_init_Zr(r2, pairing);

	element_t v, ga, gb, gc;  //公钥
	element_t* a1 = new element_t[2 * n];

	element_init_G1(v, pairing);
	element_init_G1(ga, pairing);
	element_init_G1(gb, pairing);
	element_init_G1(gc, pairing);
	for (int i = 0; i < 2 * n; ++i) {
		element_init_G1(a1[i], pairing);
	}

	element_random(g);
	element_random(a);
	element_random(b);
	element_random(c);
	element_random(r1);
	element_random(r2);

	element_pow_zn(v, g, r1);
	element_pow_zn(ga, g, a);
	element_pow_zn(gb, g, b);
	element_pow_zn(gc, g, c);
	element_t a11;
	element_init_Zr(a11, pairing);
	element_t i1;
	element_init_Zr(i1, pairing);
	for (int i = 0; i < 2 * n; ++i) {
		element_set_si(i1, i + 1);
		element_pow_zn(a11, r2, i1);
		element_pow_zn(a1[i], g, a11);
	}

	//接下来是将公钥的数据录入到文本文档中，可以转移到另一个文件进行索引构建
	fstream file("PK.txt", ios::binary | ofstream::out);
	if (!file) {
		cerr << "open PK.txt failure" << endl;
		return 0;
	}

	int len;
	len = element_length_in_bytes(g);
	unsigned char* data = new unsigned char[len];
	element_to_bytes(data, g);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	len = element_length_in_bytes(ga);
	data = new unsigned char[len];
	element_to_bytes(data, ga);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	len = element_length_in_bytes(gb);
	data = new unsigned char[len];
	element_to_bytes(data, gb);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	len = element_length_in_bytes(gc);
	data = new unsigned char[len];
	element_to_bytes(data, gc);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	len = element_length_in_bytes(v);
	data = new unsigned char[len];
	element_to_bytes(data, v);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	file.close();
	file.clear();
	//存储完毕，之后数据存储同理，都可以存储


	element_clear(a11);
	element_clear(i1);
	element_clear(r2);

	//产生cs公钥，私钥
	element_t PKcs, SKcs;
	element_init_G1(PKcs, pairing);
	element_init_Zr(SKcs, pairing);

	element_random(SKcs);
	element_pow_zn(PKcs, g, SKcs);

	element_printf("PKcs = %B\n", PKcs);
	element_printf("SKcs = %B\n", SKcs);

	file.open("PKcs.txt", ios::binary | ofstream::out);
	if (!file) {
		cerr << "open PKcs.txt failure" << endl;
		return 0;
	}

	//存储
	len = element_length_in_bytes(PKcs);
	data = new unsigned char[len];
	element_to_bytes(data, PKcs);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	len = element_length_in_bytes(SKcs);
	data = new unsigned char[len];
	element_to_bytes(data, SKcs);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	file.close();
	file.clear();


	//产生拥有者密钥
	element_t y1, y2;
	element_init_Zr(y1, pairing);
	element_init_Zr(y2, pairing);

	element_t* ek1 = new element_t[n];
	element_t* ek2 = new element_t[n];
	element_t** ht1 = new element_t * [n];
	element_t** ht2 = new element_t * [n];

	file.open("SKoi.txt", ios::binary | ofstream::out);
	if (!file) {
		cerr << "open SKoi.txt failure" << endl;
		return 0;
	}

	fstream file1("ht1.txt", ios::binary | ofstream::out);
	if (!file1) {
		cerr << "open ht1.txt failure" << endl;
		return 0;
	}

	fstream file2("ht2.txt", ios::binary | ofstream::out);
	if (!file2) {
		cerr << "open ht2.txt failure" << endl;
		return 0;
	}

	for (int i = 0; i < n; ++i) {
		ht1[i] = new element_t[n];
		ht2[i] = new element_t[2 * n];
		element_init_G1(ek1[i], pairing);
		element_init_G1(ek2[i], pairing);
		element_random(y1);
		element_random(y2);
		element_pow_zn(ek1[i], PKcs, y1);
		element_pow_zn(ek2[i], v, y1);

		len = element_length_in_bytes(ek1[i]);
		data = new unsigned char[len];
		element_to_bytes(data, ek1[i]);
		file.put(len);
		file.write((char*)data, len);
		delete[] data;

		len = element_length_in_bytes(ek2[i]);
		data = new unsigned char[len];
		element_to_bytes(data, ek2[i]);
		file.put(len);
		file.write((char*)data, len);
		delete[] data;

		printf("ek%d,1 =", i + 1);
		element_printf("%B\n", ek1[i]);
		printf("ek%d,2 =", i + 1);
		element_printf("%B\n", ek2[i]);

		for (int j = 0; j < n; ++j) {
			element_init_G1(ht1[i][j], pairing);
			element_pow_zn(ht1[i][j], a1[j], y1);
			printf("h%d,%d,1 =", i + 1, j + 1);
			element_printf("%B\n", ht1[i][j]);

			len = element_length_in_bytes(ht1[i][j]);
			data = new unsigned char[len];
			element_to_bytes(data, ht1[i][j]);
			file1.put(len);
			file1.write((char*)data, len);
			delete[] data;
		}
		for (int j = 0; j < 2 * n; ++j) {
			element_init_G1(ht2[i][j], pairing);
			element_pow_zn(ht2[i][j], a1[j], y2);
			printf("h%d,%d,2 =", i + 1, j + 1);
			element_printf("%B\n", ht2[i][j]);

			len = element_length_in_bytes(ht2[i][j]);
			data = new unsigned char[len];
			element_to_bytes(data, ht2[i][j]);
			file2.put(len);
			file2.write((char*)data, len);
			delete[] data;
		}
	}

	file.close();
	file.clear();
	file1.close();
	file1.clear();
	file2.close();
	file2.clear();

	element_clear(y1);
	element_clear(y2);


	//产生访问者密钥
	//先假设只有一个访问者（此处属性值用字符串表示，便于哈希,此处默认输入长度为5)
	vector<string> att(attri);
	//初始化，自己定义
	att[0] = "SChhk";
	att[1] = "ABCDF";
	att[2] = "scsds";
	att[3] = "aaaaa";
	att[4] = "aeeaa";
	att[5] = "aacaa";
	att[6] = "aafaa";

	element_t SKuap, A, VN, r3, r4;
	element_t* hash = new element_t[attri];
	element_init_G1(SKuap, pairing);
	element_init_G1(A, pairing);
	element_init_G1(r4, pairing);
	element_init_Zr(VN, pairing);
	element_init_Zr(r3, pairing);

	element_random(VN);
	element_mul(r3, VN, r1);

	vector<int> access(n);  //访问权限集合，1代表能够访问，0代表不能访问
	cout << "请输入访问权限，1代表能够访问，0代表不能访问，依次输入1~n拥有者权限(空格表示)" << endl;
	for (int i = 0; i < n; ++i) {
		cin >> access[i];
	}

	element_set1(SKuap); //进行初始化

	//进行权限判断,生成密钥
	for (int i = 1; i <= n; ++i) {
		if (access[i - 1] == 1) {
			element_pow_zn(r4, a1[n - i], r3);
			element_mul(SKuap, SKuap, r4);
		} //有权限进行相乘
	}

	element_printf("SKuap = %B\n", SKuap);

	element_t r, r5,r6;
	element_init_Zr(r, pairing);
	element_init_G1(r5, pairing);
	element_init_Zr(r6, pairing);

	element_random(r);
	element_mul(r3, a, c);
	element_sub(r3, r3, r);
	element_div(r6, r3, b);
	element_printf("r3 = %B\n", r3);
	element_printf("r6 = %B\n", r6);
	element_pow_zn(A, g, r6);


	element_printf("A = %B\n", A);

	vector<int> attacc(attri);   //属性值权限，1代表拥有属性值，0代表没有
	//同访问权限，这里直接初始化
	attacc[0] = 1;
	attacc[1] = 1;
	attacc[2] = 1;
	attacc[3] = 1;
	attacc[4] = 1;
	attacc[5] = 1;
	attacc[6] = 1;

	element_t* Aj = new element_t[attri];
	element_t* Bj = new element_t[attri];

	for (int i = 0; i < attri; ++i) {
		element_init_G1(hash[i], pairing);
		element_from_hash(hash[i], (void*)&att[i], 5);
	}

	for (int i = 0; i < attri; ++i) {
		if (attacc[i] == 1) {
			element_random(r3);
			element_pow_zn(r4, hash[i], r3);
			element_pow_zn(r5, g, r);
			element_init_G1(Aj[i], pairing);
			element_init_G1(Bj[i], pairing);
			element_mul(Aj[i], r4, r5);
			element_pow_zn(Bj[i], g, r3);
		}//有权限进行计算，得出正确值
		else {
			element_init_G1(Aj[i], pairing);
			element_init_G1(Bj[i], pairing);
			element_set0(Aj[i]);
			element_set0(Bj[i]);
		}//否则置0

		printf("Aj%d =", i + 1);
		element_printf("%B\n", Aj[i]);
		printf("Bj%d =", i + 1);
		element_printf("%B\n", Bj[i]);
	}

	file.open("hash.txt", ios::binary | ofstream::out);
	if (!file) {
		cerr << "open hash.txt failure" << endl;
		return 0;
	}

	for (int i = 0; i < attri; ++i) {
		len = element_length_in_bytes(hash[i]);
		data = new unsigned char[len];
		element_to_bytes(data, hash[i]);
		file.put(len);
		file.write((char*)data, len);
		delete[] data;
	}

	file.close();
	file.clear();

	file.open("VN.txt", ios::binary | ofstream::out);
	if (!file) {
		cerr << "open VN.txt failure" << endl;
		return 0;
	}

	len = element_length_in_bytes(VN);
	data = new unsigned char[len];
	element_to_bytes(data, VN);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	file.close();
	file.clear();

	file.open("SKuap.txt", ios::binary | ofstream::out);
	if (!file) {
		cerr << "open SKuap.txt failure" << endl;
		return 0;
	}

	len = element_length_in_bytes(SKuap);
	data = new unsigned char[len];
	element_to_bytes(data, SKuap);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	file.close();
	file.clear();

	file.open("SKuatt.txt", ios::binary | ofstream::out);
	if (!file) {
		cerr << "open SKuatt.txt failure" << endl;
		return 0;
	}

	len = element_length_in_bytes(A);
	data = new unsigned char[len];
	element_to_bytes(data, A);
	file.put(len);
	file.write((char*)data, len);
	delete[] data;

	for (int j = 0; j < attri; ++j) {
		len = element_length_in_bytes(Aj[j]);
		data = new unsigned char[len];
		element_to_bytes(data, Aj[j]);
		file.put(len);
		file.write((char*)data, len);
		delete[] data;
		len = element_length_in_bytes(Bj[j]);
		data = new unsigned char[len];
		element_to_bytes(data, Bj[j]);
		file.put(len);
		file.write((char*)data, len);
		delete[] data;
	}

	file.close();
	file.clear();

	element_clear(r3);
	element_clear(r4);
	element_clear(r5);
	element_clear(r);
	element_clear(r6);


	//释放初始化指针
	element_clear(g);
	element_clear(a);
	element_clear(b);
	element_clear(c);
	element_clear(r1);
	element_clear(v);
	element_clear(ga);
	element_clear(gb);
	for (int i = 0; i < 2 * n; ++i) {
		element_clear(a1[i]);
	}
	delete[] a1;

	//释放cs
	element_clear(PKcs);
	element_clear(SKcs);

	//释放owner
	for (int i = 0; i < n; ++i) {
		element_clear(ek1[i]);
		element_clear(ek2[i]);
	}
	delete[] ek1;
	delete[] ek2;

	for (int i = 0; i < n; ++i) {
		for (int j = 0; j < n; ++j) {
			element_clear(ht1[i][j]);
		}
		for (int j = 0; j < 2 * n; ++j) {
			element_clear(ht2[i][j]);
		}
		delete[] ht1[i];
		delete[] ht2[i];
	}
	delete[] ht1;
	delete[] ht2;

	//释放user
	element_clear(SKuap);
	element_clear(A);
	element_clear(VN);

	for (int i = 0; i < attri; ++i) {
		element_clear(Aj[i]);
		element_clear(Bj[i]);
		element_clear(hash[i]);
	}
	delete[] Aj;
	delete[] Bj;
	delete[] hash;


	pairing_clear(pairing);

	return 0;
}