//a simple student management system
#include<cstring>
#include<iostream>
#include <fstream>
#include <iomanip>
using namespace std;
//学生类
template<typename T>
class Student
{
public:
	long number = 0;
	char pa[20] = "jojojojojojojojojoo";
	char* name = pa;
	char sex = 'a';
	T English = 0, Chinese = 0, Math = 0;
	T sum = 0;
	static T sumEn;
	static T sumCh;
	static T sumMath;
	static double getAvgEn();
	static double getAvgCh();
	static double getAvgMath();
	virtual T get_total() = 0;
	T getChinese();
	T getMath();
	T getEnglish();
	template<typename T> friend ostream& operator<<(ostream&, Student<T>&);
};
template<typename T>T Student<T>::sumEn = 0;
template<typename T>T Student<T>::sumCh = 0;
template<typename T>T Student<T>::sumMath = 0;

template<typename T>double Student<T>::getAvgEn()
{
	return double(sumEn) / 10.0;
}
template<typename T>double Student<T>::getAvgCh()
{
	return double(sumCh) / 10.0;
}
template<typename T>double Student<T>::getAvgMath()
{
	return double(sumMath) / 10.0;
}
template<typename T>T Student<T>::getChinese()
{
	return Student<T>::Chinese;
}
template<typename T>T Student<T>::getMath()
{
	return Student<T>::Math;
}
template<typename T>T Student<T>::getEnglish()
{
	return Student<T>::English;
}
template<typename T>ostream& operator<<(ostream& output, Student<T>& stu)
{
	output << stu.number << '\t' << stu.name << '\t' << stu.sex << '\t' << stu.English << '\t' << stu.Chinese << '\t' << stu.Math << '\t' << stu.sum << endl;
	return output;
}

//理科生
template<typename T>
class ScienceStudent :public Student<T>
{
public:
	T Physics = 0, Chemistry = 0, Biology = 0;
	template<typename T> friend istream& operator >>(istream& input, ScienceStudent<T>& st);
	template<typename T> friend ostream& operator <<(ostream& output, ScienceStudent<T>& st);
	static T sumPh, sumCh, sumBio;
	static void get_average();
	T get_total();
	void input(ifstream&);
};

template<typename T>T ScienceStudent<T>::sumPh = 0;
template<typename T>T ScienceStudent<T>::sumCh = 0;
template<typename T>T ScienceStudent<T>::sumBio = 0;
template<typename T>istream& operator>>(istream& input, ScienceStudent<T>& st)
{
	input >> st.number >> st.name >> st.sex >> st.English >> st.Chinese >> st.Math >> st.Physics >> st.Chemistry >> st.Biology;
	st.sum = st.English + st.Chinese + st.Math + st.Physics + st.Chemistry + st.Biology;
	Student<T>::sumEn += st.English;
	Student<T>::sumCh += st.Chinese;
	Student<T>::sumMath += st.Math;
	ScienceStudent<T>::sumPh += st.Physics;
	ScienceStudent<T>::sumCh += st.Chemistry;
	ScienceStudent<T>::sumBio += st.Biology;
	return input;
}
template<typename T>ostream& operator<<(ostream& output, ScienceStudent<T>& st)
{
	output << setw(10) << st.number << setw(20) << st.name << setw(3) << st.sex << setw(10) << st.English << setw(10) << st.Chinese << setw(10) << st.Math << setw(10) << st.Physics << setw(10) << st.Chemistry << setw(10) << st.Biology;
	return output;
}

template<typename T>void ScienceStudent<T>::get_average()
{
	cout << "the average of physics:" << double(sumPh) / 5.0 << '\t' << "chemistry:" << double(sumCh) / 5.0 << '\t' << "biology:" << double(sumBio) / 5.0 << endl;
}
template<typename T>T ScienceStudent<T>::get_total()
{
	return Student<T>::sum;
}
template<typename T>
void ScienceStudent<T>::input(ifstream& fin)
{
	fin >> Student<T>::number >> Student<T>::name >> Student<T>::sex >> Student<T>::English >> Student<T>::Chinese >>Student<T>::Math>> ScienceStudent<T>::Physics >> ScienceStudent<T>::Chemistry >> ScienceStudent<T>::Biology;
	Student<T>::sum = Student<T>::English + Student<T>::Chinese + Student<T>::Math + ScienceStudent<T>::Physics + ScienceStudent<T>::Chemistry + ScienceStudent<T>::Biology;
}

//文科生
template<typename T>
class LiberalArtsStudent :public Student<T>
{
public:
	T History = 0, Geography = 0, Politics = 0;
	template<typename T> friend istream& operator >>(istream& input, LiberalArtsStudent<T>& st);
	template<typename T> friend ostream& operator <<(ostream& output, LiberalArtsStudent<T> st);
	static T sumHis, sumGeo, sumPol;
	static void get_average();
	T get_total();
	void input(ifstream&);
};
template<typename T>T LiberalArtsStudent<T>::sumHis = 0;
template<typename T>T LiberalArtsStudent<T>::sumGeo = 0;
template<typename T>T LiberalArtsStudent<T>::sumPol = 0;
template<typename T>istream& operator>>(istream& input, LiberalArtsStudent<T>& st)
{
	input >> st.number >> st.name >> st.sex >> st.English >> st.Chinese >> st.Math >> st.History >> st.Geography >> st.Politics;
	st.sum = st.English + st.Chinese + st.Math + st.History + st.Geography + st.Politics;
	Student<T>::sumEn += st.English;
	Student<T>::sumCh += st.Chinese;
	Student<T>::sumMath += st.Math;
	LiberalArtsStudent<T>::sumHis += st.History;
	LiberalArtsStudent<T>::sumGeo += st.Geography;
	LiberalArtsStudent<T>::sumPol += st.Politics;
	return input;
}
template<typename T>ostream& operator<<(ostream& output, LiberalArtsStudent<T> st)
{
	output <<setw(10) << st.number << setw(20) << st.name << setw(3) << st.sex << setw(10) << st.English << setw(10) << st.Chinese << setw(10) << st.Math << setw(10) << st.History << setw(10) << st.Geography << setw(10) << st.Politics;
	return output;
}

template<typename T>void LiberalArtsStudent<T>::get_average()
{
	cout << "the average of history:" << double(sumHis) / 5.0 << '\t' << "Geography:" << double(sumGeo) / 5.0 << '\t' << "Politics:" << double(sumPol) / 5.0 << endl;
}
template<typename T>T LiberalArtsStudent<T>::get_total()
{
	return Student<T>::sum;
}
template<typename T>
void LiberalArtsStudent<T>::input(ifstream& fin)
{
	fin >> Student<T>::number >> Student<T>::name >> Student<T>::sex >> Student<T>::English >> Student<T>::Chinese>>Student<T>::Math >> LiberalArtsStudent<T>::History >> LiberalArtsStudent<T>::Geography >> LiberalArtsStudent<T>::Politics;
	Student<T>::sum= Student<T>::English +Student<T>::Chinese + Student<T>::Math +LiberalArtsStudent<T>::History + LiberalArtsStudent<T>::Geography + LiberalArtsStudent<T>::Politics;
}

template<typename T>void ToSort(Student<T>** st, int n)
{
	int i, j;
	int work;
	for (i = 1; i < n; i++)
	{
		work = 0;
		for (j = 0; j < n - i; j++)
		{
			if (st[j]->get_total() < st[j + 1]->get_total())
			{
				swap(st[j], st[j + 1]);
				work = 1;
			}
			else
				if (st[j]->get_total() == st[j + 1]->get_total())
					if (st[j]->getChinese() < st[j + 1]->getChinese())
					{
						swap(st[j], st[j + 1]);
						work = 1;
					}
					else
						if (st[j]->getChinese() == st[j + 1]->getChinese())
							if (st[j]->getMath() < st[j + 1]->getMath())
							{
								swap(st[j], st[j + 1]);
								work = 1;
							}
							else
								if (st[j]->getMath() == st[j + 1]->getMath())
									if (st[j]->getEnglish() < st[j + 1]->getEnglish())
									{
										swap(st[j], st[j + 1]);
										work = 1;
									}
		}
		if (!work)
			break;
	}
}

template<typename T>void ToSort(ScienceStudent<T>** st, int n)
{
	int i, j;
	int work;
	for (i = 1; i < n; i++)
	{
		work = 0;
		for (j = 0; j < n - i; j++)
		{
			if (st[j]->get_total() < st[j + 1]->get_total())
			{
				swap(st[j], st[j + 1]);
				work = 1;
			}
			else
				if (st[j]->get_total() == st[j + 1]->get_total())
					if (st[j]->getChinese() < st[j + 1]->getChinese())
					{
						swap(st[j], st[j + 1]);
						work = 1;
					}
					else
						if (st[j]->getChinese() == st[j + 1]->getChinese())
							if (st[j]->getMath() < st[j + 1]->getMath())
							{
								swap(st[j], st[j + 1]);
								work = 1;
							}
							else
								if (st[j]->getMath() == st[j + 1]->getMath())
									if (st[j]->getEnglish() < st[j + 1]->getEnglish())
									{
										swap(st[j], st[j + 1]);
										work = 1;
									}
		}
		if (!work)
			break;
	}
}
template<typename T>void ToSort(LiberalArtsStudent<T>** st, int n)
{
	int i, j;
	int work;
	for (i = 1; i < n; i++)
	{
		work = 0;
		for (j = 0; j < n - i; j++)
		{
			if (st[j]->get_total() < st[j + 1]->get_total())
			{
				swap(st[j], st[j + 1]);
				work = 1;
			}
			else
				if (st[j]->get_total() == st[j + 1]->get_total())
					if (st[j]->getChinese() < st[j + 1]->getChinese())
					{
						swap(st[j], st[j + 1]);
						work = 1;
					}
					else
						if (st[j]->getChinese() == st[j + 1]->getChinese())
							if (st[j]->getMath() < st[j + 1]->getMath())
							{
								swap(st[j], st[j + 1]);
								work = 1;
							}
							else
								if (st[j]->getMath() == st[j + 1]->getMath())
									if (st[j]->getEnglish() < st[j + 1]->getEnglish())
									{
										swap(st[j], st[j + 1]);
										work = 1;
									}
		}
		if (!work)
			break;
	}
}

template<typename T>void input(ScienceStudent<T>*, int, string);
template<typename T>void output(ScienceStudent<T>**, int);
template<typename T>void input(LiberalArtsStudent<T>*, int, string);
template<typename T>void output(LiberalArtsStudent<T>**, int);
template<typename T>void Merge(string, ScienceStudent<T>**, LiberalArtsStudent<T>**, int, int);
int main()
{
	ScienceStudent<double> stu_ss[5];
	ScienceStudent<double>* stu_s[5];
	LiberalArtsStudent<double> stu_las[5];
	LiberalArtsStudent<double>* stu_la[5];
	fstream fin;
	int i;
	int j = 0;
	//从文件SiceceStudent.txt读入理科生成绩
	input(stu_ss, 5, "SiceceStudent.txt");
	for (i = 0; i < 5; i++)
	{
		stu_s[i] = &stu_ss[i];
	}
	cout << "\n理科生成绩单：\n"
		<< setw(10) << "学号" << setw(20) << "姓名" << setw(3) << "性别" << setw(10) << "英语" << setw(10) << "语文"
		<< setw(10) << "数学" << setw(10) << "物理" << setw(10) << "化学" << setw(10) << "生物" << setw(10) << "总分" << endl;
	//输出理科生成绩单
	output(stu_s, 5);
	//从文件LiberalArtsStudent.txt读入文科生成绩
	input(stu_las, 5, "LiberalArtsStudent.txt");
	for (i = 0; i < 5; i++)
	{
		stu_la[i] = &stu_las[i];
	}
	cout << "\n文科生成绩单：\n"
		<< setw(10) << "学号" << setw(20) << "姓名" << setw(3) << "性别" << setw(10) << "英语" << setw(10) << "语文"
		<< setw(10) << "数学" << setw(10) << "历史" << setw(10) << "地理" << setw(10) << "政治" << setw(10) << "总分" << endl;
	//输出文科生成绩单
	output(stu_la, 5);
	//将理科生成绩和文科生成绩合并写入二进制文件student.dat
	Merge("student.dat", stu_s, stu_la, 5, 5);
	fin.open("student.dat", ios::in | ios::binary);
	LiberalArtsStudent<double> temp;
	cout << "\n合并后的成绩单：\n"
		<< setw(10) << "学号" << setw(20) << "姓名" << setw(3) << "性别" << setw(10) << "英语" << setw(10) << "语文"
		<< setw(10) << "数学" << setw(10) << "专业1" << setw(10) << "专业2" << setw(10) << "专业3" << setw(10) << "六科总分" << endl;
	//输出合并后的学生成绩单
	for (int i = 0; i < 10; i++)
	{
		fin.read((char*)(&temp), sizeof(temp));
		cout << temp << setw(10) << temp.get_total() << endl;
	}
	return 0;
}
template<typename T>
void input(ScienceStudent<T>* stu_ss, int number, string filename)
{
	int i;
	ifstream fin(filename, ios::in);
	for (i = 0; i < number; i++)
	{
		stu_ss[i].input(fin);
	}
	fin.close();
}
template<typename T>
void output(ScienceStudent<T>** st, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		cout << *st[i] <<setw(10) << st[i]->get_total() << endl;
	}
}
template<typename T>
void input(LiberalArtsStudent<T>* stu_la, int number, string filename)
{
	int i;
	ifstream fin(filename, ios::in | ios::out);
	for (i = 0; i < number; i++)
	{
		stu_la[i].input(fin);
	}
	fin.close();
}
template<typename T>
void output(LiberalArtsStudent<T>** st, int n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		cout << *st[i] << setw(10) << st[i]->get_total() << endl;
	}
}
template<typename T>
void Merge(string filename, ScienceStudent<T>**stu_s, LiberalArtsStudent<T>**stu_la, int snum, int lnum)
{
	fstream fin;
	fin.open(filename, ios::out | ios::binary);
	Student<T>* ps[10];
	int i;
	for (int i = 0; i < snum + lnum; i++)
	{
		if (i < snum)
			ps[i] = stu_s[i];
		else
			ps[i] = stu_la[i - snum];
	}
	ToSort(ps, snum + lnum);
	for (int i = 0; i < snum + lnum; i++)
	{
		fin.write((char*)(ps[i]), sizeof(ScienceStudent<T>));
	}
	fin.close();
}