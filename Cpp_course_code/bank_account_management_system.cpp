//a simple bank account management system
#include<iostream>
#include<string>
#include<fstream>
#include<conio.h>
using namespace std;

class record
{
public:
	record* next;
	string type;//in or out
	string ac;
	double money;
	int year, month;
	static int num;
	record();
	~record();
	friend istream& operator>>(istream&, record&);
	friend ostream& operator<<(ostream&, record&);
};
int record::num = 0;
record::record()
{
	num++;
}
record::~record()
{
	record* next = NULL;
}
istream& operator>>(istream& input, record& r)
{
	input >> r.type >> r.ac >> r.money >> r.year >> r.month;
	return input;
}
ostream& operator<<(ostream& output, record& r)
{
	output << r.type << '\t' << r.ac << '\t' << r.money << '\t' << r.year << '\t' << r.month << endl << endl;
	return output;
}


class human					//人类
{
public:
	string name;
	string ID;
	string sex;
	string address;
	string age;
	string passwd;
	void show();
	virtual void changeinfo() = 0;
	virtual void outfile(ostream&)=0;
};
void human::show()
{
	cout << "姓名:" << name << '\n' << "身份证号:" << ID << '\n' << "性别:" << sex << endl << "居住地址:" << address << endl << "年龄:" << age << endl;
}

class user :public human				//用户类 id_u:2000?
{
public:
	string ac;
	int status = 0;
	virtual void showinfo(int y,int m)=0;								//显示个人信息
	virtual int save(double amount, int year, int month) = 0;//存钱，账户号，数额
	virtual int take(double amount, int year, int month) = 0;//取钱，账户号，数额
};


//活期存款类 ac:210??
class current_deposit :public user
{
public:
	double saving;
	double interest;
	int year, month;//起始时间，取款的时候要计算时间
	current_deposit();
	friend istream& operator>>(istream& input, current_deposit& c);
	void showinfo(int y,int m);								//显示个人信息
	int save(double amount, int year, int month);//存钱，账户号，数额
	int take(double amount, int year, int month);//取钱，账户号，数额
	void outfile(ostream& out);
	void changeinfo();
};
current_deposit::current_deposit()
{
	saving = 0;
	interest = 0;
	year = 0;
	month = 0;
}
void current_deposit::changeinfo()
{
	cout << "请输入修改后的信息：" << endl;
	cout << "密码\t姓名\t家庭地址\t年龄\n";
	cin >> passwd >> name >> address >> age;
}


void current_deposit::showinfo(int y,int m)
{
	if (year < y || (year == y && month <= m))
	{
		int i, n;
		n = (y - year) * 12 + m - month;
		for (i = 0; i < n; i++)
		{
			interest = saving * 0.0035 / 12;
			saving += interest;
		}
		year = y;
		month = m;
	}
	else
	{
		cout << "时间输入错误" << endl << endl;
	}
	cout << "账户号:" << ac << endl;
	show();
	cout << "状态:";
	switch (status)
	{
	case 0:cout << "正常"; break;
	case 1:cout << "该账户已被冻结"; break;
	}
	cout << endl;
	cout << "存款：" << saving << endl;
	if (!(year && month))
	{
		cout << "该账户尚未存款" << endl;
	}
	cout << endl;
}

istream& operator>>(istream& input, current_deposit& a)
{
	input >> a.ac >> a.passwd >> a.name >> a.ID >> a.sex >> a.address >> a.age >> a.status>> a.saving >> a.interest >> a.year >> a.month;
	return input;
}

void current_deposit::outfile(ostream& out)
{
	out << ac << endl << passwd << endl << name << endl << ID << endl << sex << endl << address << endl << age << endl << status << endl << saving << endl << interest << endl << year << endl << month << endl;
}

int current_deposit::save(double amount, int y, int m)
{
	if (status)
	{
		return -1;//冻结
	}
	else
	{
		if (!saving)
		{
			year = y;
			month = m;
			saving = amount;
			return 1;//存款成功
		}
		else
		{
			if (year < y || (year == y && month <= m))
			{
				int i, n;
				n = (y - year) * 12 + m - month;
				for (i = 0; i < n; i++)
				{
					interest = saving * 0.0035 / 12;
					saving += interest;
				}
				saving += amount;
				year = y;
				month = m;
				return 1;//成功
			}
			else
			{
				return -2;//时间错误
			}
		}
	}
}

int current_deposit::take(double amount, int y, int m)
{
	if (status)
	{
		return -1;//被冻结
	}
	else
	{
			if (year < y || (year == y && month <= m))
			{
				int i, n;
				n = (y - year) * 12 + m - month;
				for (i = 0; i < n; i++)
				{
					interest = saving * 0.0035 / 12;
					saving += interest;
				}		
				if (saving < amount)
				{
				return 0;  //余额不足
				}
				else
				{
				saving -= amount;
				year = y;
				month = m;
				return 1;//成功
				}
			}
			else
			{
				return -2;  //时间输入错误
			}
	
	}
}






//定期存款类 ac:220??
class fixed_deposit :public user
{
public:
	double saving;
	int year , month ,time ;
	double interest;
	fixed_deposit();
	friend istream& operator>>(istream& input, fixed_deposit& f);
	void showinfo(int y,int m);								//显示个人信息
	int save(double amount, int year, int month);//存钱，账户号，数额
	int take(double amount, int year, int month);//取钱，账户号，数额
	void outfile(ostream& out);
	void changeinfo();
};
fixed_deposit::fixed_deposit()
{
	saving = 0;
	interest = 0;
	year = 0;
	month = 0;
	time = 0;
}
void fixed_deposit::changeinfo()
{
	cout << "请输入修改后的信息：" << endl;
	cout << "密码\t姓名\t家庭地址\t年龄\n";
	cin >> passwd >> name >> address >> age;
}
void fixed_deposit::showinfo(int y,int m)
{
	double rate;
	switch (time)
	{
	case 1:rate = 0.0225; break;
	case 2:rate = 0.0275; break;
	case 3:rate = 0.0325; break;
	case 5:rate = 0.0335; break;
	default:rate = 0; break;
	}
	cout << "账户号：" << ac << endl;
	show();
	cout << "状态:";
	switch (status)
	{
	case 0:cout << "正常"; break;
	case 1:cout << "该账户已被冻结"; break;
	}
	cout << endl;
	cout << "存款：" << saving << endl;
	cout << "到期可得利息：" << saving * time * rate << endl;
	if (year && month)
	{
		cout << "存款时间:" << year << "年" << month << "月" << endl;
		cout << "存款期限：" << time << "年" << endl;
	}
	else
	{
		cout << "该账户尚未存款" << endl;
	}
	cout << endl;
}
istream& operator>>(istream& input, fixed_deposit& c)
{
	input >> c.ac >> c.passwd >> c.name >> c.ID >> c.sex >> c.address >> c.age >> c.status >> c.saving >> c.interest >> c.year >> c.month>>c.time;
	return input;
}

void fixed_deposit::outfile(ostream& out)
{
	out << ac << endl << passwd << endl << name << endl << ID << endl << sex << endl << address << endl << age << endl << status<< endl << saving << endl << interest << endl << year << endl << month << endl<<time<<endl;
}

int fixed_deposit::save(double amount, int y, int m)
{
	if (!status) 
	{
		if (saving == 0)
		{
			saving = amount;
			year = y;
			month = m;
			return 1;//存钱成功
		}
		else
		{
			return 0;//无法存入
		}
	}
	else
	{
		return -1;//被冻结
	}
}

int fixed_deposit::take(double amount, int y, int m)
{
	double rate;
	switch (time)
	{
	case 1:rate = 0.0225; break;
	case 2:rate = 0.0275; break;
	case 3:rate = 0.0325; break;
	case 5:rate = 0.0335; break;
	default:rate = 0; break;
	}
	if (!status)
	{

			if (y < year || (year == y && m < month))
			{
				return -2;//时间错误
			}
			else
			{
				if ((y-year)*12+m-month>=time*12)
				{
					interest = saving * rate * time;
					saving += interest;
					if (saving < amount)
					{
						return 0;//余额不足
					}
					else
					{
					saving -= amount;
					year = y;
					month = m;
					time = 0;
					return 1;//取钱成功
					}
				}
				else
				{
					int i, n;
					n = (y - year) * 12 + m - month;
					for (i = 0; i < n; i++)
					{
						interest = saving * 0.0035 / 12;
						saving += interest;
					}
					if (saving < amount)
					{
						return 0;//余额不足
					}
					else
					{
					saving -= amount;
					year = y;
					month = m;
					time = 0;
					return 1;//成功
					}
				}
			}
	}
	else
	{
		return -1;//被冻结
	}
}









//储蓄类 ac:2000?
class normal_deposit :public user
{
public:
	double saving;
	normal_deposit();
	friend istream& operator>>(istream& input, normal_deposit& f);
	void showinfo(int y,int m);								//显示个人信息
	int save(double amount, int year, int month);//存钱，账户号，数额
	int take(double amount, int year, int month);//取钱，账户号，数额
	void outfile(ostream& out);
	void changeinfo();
};
/*normal_deposit::normal_deposit(string n, string i, string s, string ad, string p, string a, string id,string acn, int sa):user(n, i, s, ad, p, a, id), saving(sa),ac(acn)
{
	//写入文件
}*/
normal_deposit::normal_deposit()
{
	saving = 0;
}
void normal_deposit::changeinfo()
{
	cout << "请输入修改后的信息：" << endl;
	cout << "密码\t姓名\t家庭地址\t年龄\n";
	cin >> passwd >> name >> address >> age;
}
void normal_deposit::showinfo(int y,int m)
{
	cout << "账户号：" << ac << endl;
	show();
	cout << "状态:";
	switch (status)
	{
	case 0:cout << "正常"; break;
	case 1:cout << "该账户已被冻结"; break;
	}
	cout << endl;
	cout << "余额：" << saving << endl;
	cout << endl;
}
istream& operator>>(istream& input, normal_deposit& c)
{
	input >> c.ac >> c.passwd >> c.name >> c.ID >> c.sex >> c.address >> c.age >>c.status>> c.saving;
	return input;
}

void normal_deposit::outfile(ostream& out)
{
	out << ac << endl << passwd << endl << name << endl << ID << endl << sex << endl << address << endl << age << endl << status<< endl << saving << endl;
}

int normal_deposit::save(double amount, int year, int month)
{
	if (status)
	{
		return -1;//被冻结
	}
	else 
	{
		saving += amount;
		return 1;//成功
	}
}

int normal_deposit::take(double amount, int year, int month)
{
	if (status)
	{
		return -1;//冻结
	}
	else
	{
		if (saving < amount)
		{
			return 0;//余额不足
		}
		else
		{
			saving -= amount;
			return 1;//成功
		}
	}
}





class manager:public human			//员工类
{
protected:
	string id_m;					//员工号
public:
	virtual void showinfo() = 0;
	virtual void cancelp(string) = 0;
	string showid();
};
string manager::showid()
{
	return id_m;
}

class employer:public manager			//职员类 id_m:1000? ?表示第几个
{
public:
	void showinfo();
	void changeinfo();
	void addp(string id);
	void cancelp(string);
	void ice(string);
	void uice(string);
	friend istream& operator>>(istream& input, employer& e);
	void outfile(ostream&);
};
void employer::showinfo()
{
	cout << "员工号：" << id_m << endl;
	show();
	cout << endl;
}

void employer::changeinfo()
{
	cout << "请输入修改后的信息：" << endl;
	cout << "密码\t姓名\t家庭地址\t年龄\n";
	cin >> passwd >> name >> address >> age;
}

void employer::addp(string id)
{
	if (id[1] == '0')
	{
		normal_deposit a;
		cout << "请按顺序输入账户号，密码，名字，身份证号码，性别，家庭地址，年龄：" << endl;
		cin >> a.ac >> a.passwd >> a.name >> a.ID >> a.sex >> a.address >> a.age;
		cout << endl;
		ofstream out(id+".txt", ios::out);
		a.outfile(out);
		out.close();
		cout << "增加成功" << endl<<endl;
	}
	else
	{
		if (id[1] == '1')
		{
			current_deposit a;
			cout << "请按顺序输入账户号，密码，名字，身份证号码，性别，家庭地址，年龄：" << endl;
			cin >> a.ac >> a.passwd >> a.name >> a.ID >> a.sex >> a.address >> a.age;
			ofstream out(id + ".txt", ios::out);
			a.outfile(out);
			out.close();
		}
		else
		{
			if (id[1] == '2') 
			{
				fixed_deposit a;
				cout << "请按顺序输入账户号，密码，名字，身份证号码，性别，家庭地址，年龄,存款时长：" << endl;
				cin >> a.ac >> a.passwd >> a.name >> a.ID >> a.sex >> a.address >> a.age>> a.time;
				ofstream out(id + ".txt", ios::out);
				a.outfile(out);
				out.close();
			}
			else
			{
				cout << "输入账户号错误。" << endl;
			}
		}
	}
}

void employer::cancelp(string id)
{
	id += ".txt";
	ofstream out(id, ios::out);
	out.close();
	cout << endl;
}

void employer::ice(string id)
{
	ifstream fin(id+".txt",ios::in);
	if (id[1] == '0')
	{
		normal_deposit a;
		fin >> a;
		fin.close();
		a.status = 1;
		ofstream out(id + ".txt", ios::out);
		a.outfile(out);
		out.close();
	}
	else
	{
		if (id[1] == '1')
		{
			current_deposit a;
			fin >> a;
			fin.close();
			a.status = 1;
			ofstream out(id + ".txt", ios::out);
			a.outfile(out);
			out.close();
		}
		else
		{
			if (id[1] == '2')
			{
				fixed_deposit a;
				fin >> a;
				fin.close();
				a.status = 1;
				ofstream out(id + ".txt", ios::out);
				a.outfile(out);
				out.close();
			}
			else
			{
				cout << "输入账户号错误。" << endl;
			}
		}
	}
}
void employer::uice(string id)
{
	ifstream fin(id + ".txt", ios::in);
	if (id[1] == '0')
	{
		normal_deposit a;
		fin >> a;
		fin.close();
		a.status = 0;
		ofstream out(id + ".txt", ios::out);
		a.outfile(out);
		out.close();
	}
	else
	{
		if (id[1] == '1')
		{
			current_deposit a;
			fin >> a;
			fin.close();
			a.status = 0;
			ofstream out(id + ".txt", ios::out);
			a.outfile(out);
			out.close();
		}
		else
		{
			if (id[1] == '2')
			{
				fixed_deposit a;
				fin >> a;
				fin.close();
				a.status = 0;
				ofstream out(id + ".txt", ios::out);
				a.outfile(out);
				out.close();
			}
			else
			{
				cout << "输入账户号错误。" << endl;
			}
		}
	}
}

istream& operator>>(istream& input, employer& e)
{
	input >> e.id_m >> e.passwd >> e.name >> e.ID >> e.sex >> e.address >> e.age;
	return input;
}

void employer::outfile(ostream& out)
{
	out << id_m <<endl<< passwd << endl << name << endl << ID << endl << sex << endl << address << endl << age << endl;
}

class director :public manager			//主管类 id_m:00000
{
public:
	void addp();
	void showinfo();
	void changeinfo();
	void outfile(ostream& out);
	void cancelp(string);
	friend istream& operator>>(istream& input,director& boss);
};
void director::showinfo()
{
	cout << "员工号：" << id_m << endl;
	show();
	cout << endl;
}

void director::addp()
{
	employer c;
	cout << "员工号\t密码\t姓名\t身份证号\t性别\t家庭地址\t年龄\n";
	cin >> c;
	cout << endl;
	string id = c.showid() + ".txt";
	ofstream out(id, ios::out);
	c.outfile(out);
	out.close();
	cout << "增加成功" << endl;
}

void director::cancelp(string id)
{
	id += ".txt";
	ofstream out(id, ios::out);
	out.close();
	cout << endl;
}

istream& operator>>(istream& input, director& boss)
{
	input >> boss.id_m >> boss.passwd >> boss.name >> boss.ID >> boss.sex >> boss.address >> boss.age;
	return input;
}

void director::changeinfo()
{
	cout << "请输入修改后的信息：" << endl;
	cout << "密码\t姓名\t家庭地址\t年龄\n";
	cin >> passwd >> name >> address >> age;
	cout << endl;
}

void director::outfile(ostream& out)
{
	out << id_m << endl << passwd << endl << name << endl << ID << endl << sex << endl << address << endl << age << endl;
}








int log_in(string id,string pwd);
bool checkuser(string id);
void build(record*, string);
void Sort(record*&,int,int);
void display(record*);
void menu();
int main()
{//只要设置好文件名格式后直接找就好了，并不用这么麻烦
	while (1)
	{
		menu();
	}
}

int log_in(string id, string pwd)
{
	ifstream fin;
	string s;
	string pass;
	id += ".txt";
	fin.open(id, ios::in);
	fin >> s;
	fin >> pass;
	if (!fin)
	{
		cout << "该用户不存在";
		cout << endl;
	}
	else 
{
	if (pwd == pass)
	{
		if (id[0] == '0')
		{
			fin.close();
			return 0;
		}
		else
		{
			if (id[0] == '1')
			{
				fin.close();
				return 1;
			}
			else
			{
				if (id[0] == '2')
				{
					fin.close();
					return 2;
				}
				else
				{
					fin.close();
					return -1;//帐号格式错误
				}
			}
		}

	}
	else
	{
		fin.close();
		return -2;//密码错误
	}
}
}

bool checkuser(string id)
{
	ifstream fin;
	if (id[0] == '2' && (id[1] == '0' || id[1] == '1' || id[1] == '2'))
	{
		fin.open(id + ".txt", ios::_Nocreate);
		if (!fin)
		{
			cout << "该用户不存在" << endl;
			fin.close();
			return false;
		}
		else
		{
			fin.close();
			return true;
		}
	}
	else
	{
		cout << "输入的帐号不是用户帐号。" << endl;
		return false; 
	}
		
}

void build(record* head, string filename)
{
	record* s,*p=head;
	ifstream fin(filename + ".txt", ios::in);
	if (fin >> *p)
	{		
		p->num = 1;
		s = new record;
		p->next = s;
		while (fin >> *s)
		{
			s = new record;
			p = p->next;
			p->next = s;
		}
		p->next = NULL;
		delete s;
		p->num--;
	}
	fin.close();
}

//根据不同要求进行排序,type表示根据什么排序，如：0表示时间，1表示金额，order表示升序还是降序,如0表示降序,1表示升序
void Sort(record*& head, int type, int order)
{
	int i,j;
	record** array = new record * [head->num];
	record* p;
	p = head;
	array[0] = head;
	for(i=1;p->next!=NULL;i++)
	{
		p = p->next;
		array[i] = p;
	}
	if (order==1)//升序(从小到大/从过去到最近)
	{
		if (type==1)//金额
		{
			for (i = 0; i < head->num; i++)
			{
				for (j = 0; j < head->num-i-1; j++)
				{
					if (array[j]->money > array[j + 1]->money)
					{
						p = array[j];
						array[j] = array[j + 1];
						array[j + 1] = p;
					}
				}
			}
			head = array[0];
			p = head;
			for (i = 1; i < head->num; i++)
			{
				p->next = array[i];
				p = p->next;
			}
			p->next = NULL;
		}
		else
		{
			if (type == 0)//时间
			{
				for (i = 0; i < head->num; i++)
				{
					for (j = 0; j < head->num - i - 1; j++)
					{
						if (array[j]->year * 12 + array[j]->month > array[j + 1]->year * 12 + array[j + 1]->month)
						{
							p = array[j];
							array[j] = array[j + 1];
							array[j + 1] = p;
						}
					}
				}
				head = array[0];
				p = head;
				for (i = 1; i < head->num; i++)
				{
					p->next = array[i];
					p = p->next;
				}
				p->next = NULL;
			}
			else
				cout << "输入有误" << endl << endl;
		}
	}
	else
	{
		if (order == 0)//降序(从大到小/从现在到过去)
		{
			if (type == 1)//金额
			{
				for (i = 0; i < head->num; i++)
				{
					for (j = 0; j < head->num - i - 1; j++)
					{
						if (array[j]->money < array[j + 1]->money)
						{
							p = array[j];
							array[j] = array[j + 1];
							array[j + 1] = p;
						}
					}
				}
				head = array[0];
				p = head;
				for (i = 1; i < head->num; i++)
				{
					p->next = array[i];
					p = p->next;
				}
				p->next = NULL;
			}
			else
			{
				if (type == 0)//时间
				{
					for (i = 0; i < head->num; i++)
					{
						for (j = 0; j < head->num - i - 1; j++)
						{
							if (array[j]->year * 12 + array[j]->month < array[j + 1]->year * 12 + array[j + 1]->month)
							{
								p = array[j];
								array[j] = array[j + 1];
								array[j + 1] = p;
							}
						}
					}
					head = array[0];
					p = head;
					for (i = 1; i < head->num; i++)
					{
						p->next = array[i];
						p = p->next;
					}
					p->next = NULL;
				}
				else
					cout << "输入有误" << endl << endl;
			}
		}
		else
			cout << "输入有误" << endl << endl;
	}
	delete array;
}

void display(record* head)
{
	record* p = head;
	while (p != NULL)
	{
		cout << p->type << '\t' << p->ac << "\t" << p->money << "\t" << p->year << "年" << p->month << "月" << endl;
		p = p->next;
	}
	cout << endl;
}

void menu()
{
	int com;
	string id;
	string passwd;
	cout << "****************************************" << endl;
	cout << "**                                    **" << endl;
	cout << "**          银行账户管理系统          **" << endl;
	cout << "**                                    **" << endl;
	cout << "****************************************" << endl;
	int year, month;
	cout << "请输入目前的年份：" << endl;
	cin >> year;
	cout << endl;
	cout << "请输入目前的月份：" << endl;
	cin >> month;
	cout << endl;
	cout << "请输入员工/用户帐号：" << endl;
	cin >> id;
	cout << "请输入密码：" << endl;
	char ch;
	while (1)
	{
		ch = _getch();
		if (ch == '\r')
		{
			break;
		}
		else
		{
			passwd += ch;
			cout << '*';
		}
	}
	cout << endl;
	int lognum = log_in(id, passwd);
	switch (lognum)
	{
	case -2:
	{
		cout << "密码错误。" << endl;
		break;
	}
	case -1:
	{
		cout << "账号格式错误。" << endl;
		break;
	}
	case 0:
	{
		int flag = 0;
		while (!flag)
		{
			cout << "请选择你要进行的操作：\n1.显示个人信息\n2.修改个人信息\n3.增加员工\n4.删除员工\n5.退出系统" << endl;
			cin >> com;
			cout << endl;
			director boss;
			ifstream fin(id + ".txt", ios::in);
			fin >> boss;
			fin.close();
			switch (com)
			{
			case 1:
			{
				boss.showinfo();
				break;
			}
			case 2:
			{
				boss.changeinfo();
				ofstream out(id + ".txt", ios::out);
				boss.outfile(out);
				out.close();
				cout << "修改成功" << endl << endl;
				break;
			}
			case 3:
			{
				boss.addp();
				cout << endl;
				break;
			}
			case 4:
			{
				cout << "请输入删除员工的员工号：" << endl;
				string idt;
				cin >> idt;
				boss.cancelp(idt);
				cout << "删除成功" << endl << endl;
				break;
			}
			case 5:
			{
				flag++;
				break;
			}
			default:cout << "输入错误" << endl << endl; break;
			}
		}
		break;
	}
	case 1://职员类
	{
		int flag = 0;
		string r = "record";
		record* head = new record;
		head->num = 0;
		build(head, r);
		while (!flag)
		{
			cout << "请选择你要进行的操作：\n1.显示个人信息\n2.修改个人信息\n3.增加账户\n4.删除账户\n5.冻结账户\n6.解冻账户\n7.查看交易记录\n8.退出系统" << endl;
			cin >> com;
			cout << endl;
			ifstream fin(id + ".txt", ios::in);
			employer worker;
			fin >> worker;
			fin.close();
			switch (com)
			{
			case 1:
			{
				worker.showinfo();
				break;
			}
			case 2:
			{
				worker.changeinfo();

				ofstream out(id + ".txt", ios::out);
				worker.outfile(out);
				out.close();
				cout << "修改成功" << endl << endl;
				break;
			}
			case 3:
			{
				cout << "请输入新增账户的账户号：" << endl;
				string a;
				cin >> a;
				if (a[0] == '2' && (a[1] == '0' || a[1] == '1' || a[1] == '2'))
				{
					worker.addp(a);
				}
				break;
			}
			case 4:
			{
				cout << "请输入删除账户的账户号：" << endl;
				string idt;
				cin >> idt;
				if (checkuser(idt))
				{
					worker.cancelp(idt);
					cout << "删除成功" << endl << endl;
				}
				break;
			}
			case 5:
			{
				cout << "请输入冻结账户的账户号：" << endl;
				string idt;
				cin >> idt;
				if (checkuser(idt))
				{
					worker.ice(idt);
					cout << "冻结成功" << endl << endl;
				}
				break;
			}
			case 6:
			{
				cout << "请输入解冻账户的账户号：" << endl;
				string idt;
				cin >> idt;
				if (checkuser(idt))
				{
					worker.uice(idt);
					cout << "解冻成功" << endl << endl;
				}
				break;
			}
			case 7:
			{
				int type, order;
				cout << "请选择交易记录的排序方式：1.按时间排序 2.按金额排序：" << endl;
				cin >> type;
				type--;
				cout << "请选择交易记录的排序方式：1.降序排列 2.升序排列：" << endl;
				cin >> order;
				order--;
				if (head->num != 0)
				{
					Sort(head, type, order);
					cout << "操作\t账户号\t交易金额\t时间\n";
					display(head);
				}
				else
				{
					cout << "暂无交易记录" << endl << endl;
				}
				break;
			}
			case 8:
			{
				flag++;
				break;
			}
			default:cout << "输入错误" << endl << endl; break;
			}
		}
		break;
	}
	case 2://账户类
	{
		int flag = 0;
		string r = id + "record";
		record* head = new record;
		head->num = 0;
		build(head, r);
		while (!flag)
		{
			user* p;
			normal_deposit n;
			current_deposit c;
			fixed_deposit f;
			cout << "请选择你要进行的操作：\n1.显示账户信息\n2.修改账户信息\n3.存钱\n4.取钱\n5.转账\n6.查询交易记录\n7.退出系统" << endl;
			cin >> com;
			cout << endl;
			ifstream fin(id + ".txt", ios::in);
			if (id[1] == '0')
			{
				fin >> n;
				p = &n;
			}
			else
			{
				if (id[1] == '1')
				{
					fin >> c;
					p = &c;
				}
				else
				{
					fin >> f;
					p = &f;
				}
			}
			fin.close();
			switch (com)
			{
			case 1:
			{
				p->showinfo(year, month);
				break;
			}
			case 2:
			{
				p->changeinfo();
				ofstream out(id + ".txt", ios::out);
				p->outfile(out);
				out.close();
				cout << "修改成功" << endl << endl;
				break;
				break;
			}
			case 3:
			{
				double money;
				cout << "请输入要存入的金额：" << endl;
				cin >> money;
				int sign = p->save(money, year, month);
				ofstream out(id + ".txt", ios::out);
				p->outfile(out);
				out.close();
				switch (sign)
				{
				case -2:cout << "开始界面时间输入错误" << endl; break;
				case -1:cout << "您的账户被冻结，无法进行操作" << endl; break;
				case 0:cout << "无法存入" << endl; break;
				case 1:cout << "存款成功" << endl; out.open("record.txt", ios::app); out << "in" << " " << id << " " << money << " " << year << " " << month << " " << endl; out.close();
					out.open(r + ".txt", ios::app); out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl; out.close(); break;
				}
				cout << endl;
				break;
			}
			case 4:
			{
				double money;
				cout << "请输入要取出的金额：" << endl;
				cin >> money;
				cout << endl;
				int sign = p->take(money, year, month);
				ofstream out(id + ".txt", ios::out);
				p->outfile(out);
				out.close();
				switch (sign)
				{
				case -2:cout << "开始界面时间输入错误" << endl; break;
				case -1:cout << "您的账户被冻结，无法进行操作" << endl; break;
				case 0:cout << "余额不足" << endl; break;
				case 1:cout << "取款成功" << endl; out.open("record.txt", ios::app); out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl; out.close();
					out.open(r + ".txt", ios::app); out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl; out.close(); break;
				}
				cout << endl;
				break;
			}
			case 5:
			{
				string ac;
				cout << "请输入转入账户：\n";
				cin >> ac;
				cout << endl;
				cout << "请输入转账金额：\n";
				double money;
				cin >> money;
				if (checkuser(ac))
				{
					user* q;
					int s1, s2;
					if (ac[1] == '0')
					{
						normal_deposit n2;
						ifstream fin(ac + ".txt", ios::in);
						fin >> n2;
						fin.close();
						q = &n2;
						s1 = p->take(money, year, month);
						s2 = q->save(money, year, month);
						ofstream out(id + ".txt", ios::out);
						p->outfile(out);
						out.close();
						out.open(ac + ".txt", ios::out);
						q->outfile(out);
						out.close();
						if (s1 == 1 && s2 == 1)
						{
							cout << "转账成功" << endl;
							out.open("record.txt", ios::app);
							out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl;
							out << "in" << " " << ac << " " << money << " " << year << " " << month << " " << endl;
							out.close();
							out.open(r + ".txt", ios::app);
							out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl;
							out.close();
							out.open(ac + "record.txt", ios::app);
							out << "in" << " " << ac << " " << money << " " << year << " " << month << " " << endl;
							out.close();
						}
						else
							cout << "转账失败" << endl;
					}
					else
					{
						if (ac[1] == '1')
						{
							current_deposit n2;
							ifstream fin(ac + ".txt", ios::in);
							fin >> n2;
							fin.close();
							q = &n2;
							s1 = p->take(money, year, month);
							s2 = q->save(money, year, month);
							ofstream out(id + ".txt", ios::out);
							p->outfile(out);
							out.close();
							out.open(ac + ".txt", ios::out);
							q->outfile(out);
							out.close();
							if (s1 == 1 && s2 == 1)
							{
								cout << "转账成功" << endl;
								out.open("record.txt", ios::app);
								out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl;
								out << "in" << " " << ac << " " << money << " " << year << " " << month << " " << endl;
								out.close();
								out.open(r + ".txt", ios::app);
								out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl;
								out.open(ac + "record.txt", ios::app);
								out << "in" << " " << ac << " " << money << " " << year << " " << month << " " << endl;
								out.close();
							}
							else
								cout << "转账失败" << endl;
						}
						else
						{
							fixed_deposit n2;
							ifstream fin(ac + ".txt", ios::in);
							fin >> n2;
							fin.close();
							q = &n2;
							s1 = p->take(money, year, month);
							s2 = q->save(money, year, month);
							ofstream out(id + ".txt", ios::out);
							p->outfile(out);
							out.close();
							out.open(ac + ".txt", ios::out);
							q->outfile(out);
							out.close();
							if (s1 == 1 && s2 == 1)
							{
								cout << "转账成功" << endl;
								out.open("record.txt", ios::app);
								out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl;
								out << "in" << " " << ac << " " << money << " " << year << " " << month << " " << endl;
								out.close();
								out.open(r + ".txt", ios::app);
								out << "out" << " " << id << " " << money << " " << year << " " << month << " " << endl;
								out.open(ac + "record.txt", ios::app);
								out << "in" << " " << ac << " " << money << " " << year << " " << month << " " << endl;
								out.close();
							}
							else
								cout << "转账失败" << endl;
						}
					}
					cout << endl;
				}
				break;
			}
			case 6:
			{
				int type, order;
				cout << "请选择交易记录的排序方式：1.按时间排序 2.按金额排序：" << endl;
				cin >> type;
				type--;
				cout << "请选择交易记录的排序方式：1.降序排列 2.升序排列：" << endl;
				cin >> order;
				order--;
				if ((type==1||type==0)&&(order==1||order==0))
				{
					if (head->num != 0)
					{
						Sort(head, type, order);
						cout << "操作\t账户号\t交易金额\t时间\n";
						display(head);
					}
					else
					{
						cout << "暂无交易记录" << endl << endl;
					}
				}
				else
				{
					cout << "输入错误" << endl << endl;
				}
				break;
			}
			case 7:
			{
				flag++;
				break;
			}
			default:cout << "输入错误" << endl << endl; break;
			}
		}
		break;
	}
	}
}