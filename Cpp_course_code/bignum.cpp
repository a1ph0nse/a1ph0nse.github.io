/*used for the counting of big number
include some algorithms used in crypto such as mod_repeat_square,CRT,diffie_hellman,bezout 
*/
#pragma once
#include<iostream>
#include<iomanip>
#include<cmath>
using namespace std;
class bignum //每位的大小为0~9999
{
private:
	int array[80];//数组存bignum
	int len;//长度，多少个4位
	int sign;//符号位,0为正,1为负
public:
	bignum();
	bignum(int);
	bignum(const bignum& num);//复制构造函数
	friend bignum& contrary(bignum& num);//取相反数
	friend void add(bignum& num1, bignum& num2, bignum& result);//加数，被加数，和
	friend void sub(bignum& num1, bignum& num2, bignum& result);//被减数，减数，差
	friend void mul(bignum& num1, bignum& num2, bignum& result);//乘数，被乘数，积
	friend void div(bignum& num1, bignum& num2, bignum& result);//被除数，除数，商
	friend istream& operator>>(istream& input, bignum& num);//>>重载,从文件中输入
	friend ostream& operator<<(ostream& output, bignum& num);//<<重载,写入文件中
	friend void mod(bignum& num1, bignum& num2, bignum& result);//被除数，除数，余数
	bool operator<(bignum& num2);//小于的重载
	bool operator<=(bignum& num2);//小于等于的重载
	bignum& operator=(bignum& num);//重载赋值运算符
	//bignum square();//开方
	//friend void sieve(bignum& num, ifstream& input, ofstream& output);//筛法
	friend bool judgemod(bignum& num1, bignum& num2);//判断是否整除
	friend void get_div_mod(bignum& num1, bignum& num2);//求商和余数
	friend void cal_ggo(bignum& num1, bignum& num2,bignum& result);//求最大公因数
	friend void bezout(bignum& num1, bignum& num2, bignum& s, bignum& t);//求s和t
	friend void mod_repeat_square(bignum& b, bignum& n, bignum& m, bignum& result);//模重复平方计算法，b为底数，n为指数，m为模
	friend void diffie_hellman(bignum& p, bignum& g,bignum&R1, bignum& R2, bignum& y, bignum& k);//Diffie_Hellman密钥共享算法
	friend void CRT(bignum& x, bignum& b, bignum& m, bignum&N, bignum& result);//中国剩余定理，x为前一个同余式的xi-1，b为当前同余式的bi，m为当前同余式的mi,N为前面同余式的模之积Ni-1,result为当前两条同余式的结果xi
	friend void Fermat_Check(bignum& n,bignum& t);//费马小定理检验素数，n为要检验的素数,t为要检验的次数
};

bignum::bignum()
{
	int i;
	sign = 0;
	for (i = 0; i < 80; i++)
	{
		array[i] = 0;
	}
	len = 0;
}



bignum::bignum(int n)
{
	int i;
	sign = 0;
	for (i = 0; i < 80; i++)
	{
		array[i] = 0;
	}
	len = 0;
	if (n == 0)
	{
		;
	}
	else
	{
		if (n > 0)
		{
			sign = 0;
		}
		else
		{
			n = -n;
			sign = 1;
		}
		array[0] = n;
		i = 0;
		while (i < 80)
		{
			if (array[i] >= 10000)
			{
				array[i] -= 10000;
				array[i + 1]++;
			}
			else
			{
				i++;
			}
		}
		for (i = 79; i >= 0; i--)
		{
			if (array[i] != 0)
				break;
		}
		len = i + 1;
	}
}



bignum::bignum(const bignum& num)
{
	int i = 0;
	sign = num.sign;
	for (; i < len; i++)
	{
		array[i] = num.array[i];
	}
	len = num.len;
}



bignum& contrary(bignum& num)
{
	if (num.sign == 0)
	{
		num.sign = 1;
	}
	else
	{
		num.sign = 0;
	}
	return num;
}



void add(bignum& num1, bignum& num2, bignum& result)
{
	int i;//i用于记录计算到了哪一位
	int maxlen;//记录最多用了多少个4位
	int carry = 0;//进位/借位
	result.sign = 0;
	for (i = 0; i < 79; i++)
		result.array[i] = 0;
	result.len = 0;
	bignum temp;
	//判断是否有0
	if (num1.len == 0)
	{
		result = num2;
		return;
	}
	if (num2.len == 0)
	{
		result = num1;
		return;
	}
	//求最大位
	if (num1.len < num2.len)
	{
		maxlen = num2.len;
	}
	else
	{
		maxlen = num1.len;
	}
	//同号相加
	if (num1.sign == num2.sign)
	{
		for (i = 0; i < maxlen; i++)
		{
			result.array[i] = num1.array[i] + num2.array[i] + carry;
			if (result.array[i] >= 10000)
			{
				result.array[i] -= 10000;
				carry = 1;
			}
			else
			{
				carry = 0;
			}
		}
		if (carry)
		{
			result.array[maxlen] = 1;
			result.len = maxlen + 1;
		}
		else
		{
			result.len = maxlen;
		}
		result.sign = num1.sign;
	}
	//异号相加变为减法
	else
	{
		if (num1.sign == 0)
		{
			sub(num1, contrary(num2), result);
		}
		else
		{
			sub(num2, contrary(num1), result);
		}
	}
	return;
}



void sub(bignum& num1, bignum& num2, bignum& result)
{
	int borrow;//借位
	result.sign = 0;
	int i;
	for (i = 0; i < 79; i++)
		result.array[i] = 0;
	result.len = 0;
	//判断是否有0
	if (num2.len == 0)
	{
		result = num1;
		return;
	}
	if (num1.len == 0)
	{
		if (num2.len == 0)
		{
			result = num1;
			return;
		}
		else
		{
			result = contrary(num2);
			return;
		}
	}
	//同号
	if (num1.sign == num2.sign)
	{
		if (num1.sign == 0)//同正
		{
			if (num1 < num2)//小减大
			{
				sub(num2, num1, result);
				result = contrary(result);
				return;
			}
			else//大减小
			{
				borrow = 0;
				for (i = 0; i < num1.len; i++)
				{
					result.array[i] = num1.array[i] - num2.array[i] - borrow;
					if (result.array[i] < 0)
					{
						result.array[i] += 10000;
						borrow = 1;
					}
					else
					{
						borrow = 0;
					}
				}
				for (i = 79; i >= 0; i--)
				{
					if (result.array[i] != 0)
					{
						result.len = i + 1;
						break;
					}
				}
				result.sign = 0;
				return;
			}
		}
		else//同负
		{
			if (num1 < num2)//小减大
			{
				sub(contrary(num1), contrary(num2), result);
				result = contrary(result);
				return;
			}
			else//大减小
			{
				sub(contrary(num2), contrary(num1), result);
				return;
			}
		}
	}
	else//异号
	{
		if (num1.sign == 0)//*this为正,即正-负
		{
			add(num1, contrary(num2), result);
			return;
		}
		else//*this为负，即负-正
		{
			add(contrary(num1), num2, result);
			result = contrary(result);
			return;
		}
	}
}



void mul(bignum& num1, bignum& num2, bignum& result)
{
	int carry;//进位
	int i, j;
	int maxlen;
	result.sign = 0;
	for (i = 0; i < 79; i++)
		result.array[i] = 0;
	result.len = 0;
	if (num1.len < num2.len)
	{
		maxlen = num2.len;
	}
	else
	{
		maxlen = num1.len;
	}
	for (i = 0; i < num1.len; i++)
	{
		carry = 0;
		for (j = 0; j <= num2.len; j++)
		{
			result.array[j + i] += num1.array[i] * num2.array[j] + carry;
			if (result.array[j + i] >= 10000)
			{
				carry = result.array[j + i] / 10000;
				result.array[j + i] -= carry * 10000;
			}
			else
			{
				carry = 0;
			}
		}
	}
	for (i = 79; i >= 0; i--)
	{
		if (result.array[i] != 0)
		{
			result.len = i + 1;
			break;
		}
	}
	result.sign = num1.sign ^ num2.sign;
	return;
}



void div(bignum& num1, bignum& num2, bignum& result)
{
	bignum one(1), ten(10), ter(1);
	bignum div, temp, bediv;
	//将result初始化
	result.sign = 0;
	int i;
	for (i = 0; i < 79; i++)
		result.array[i] = 0;
	result.len = 0;
	//记录num1和num2的符号
	int sign1 = num1.sign;
	int sign2 = num2.sign;
	num1.sign = 0;
	num2.sign = 0;

	div = num1;
	while (num2 <= div)
	{
		bediv = num2;
		ter = one;
		while (bediv < div)
		{
			mul(bediv, ten, temp);
			if (div < temp)
			{
				break;
			}
			bediv = temp;
			mul(ter, ten, temp);
			ter = temp;
		}
		while (bediv <= div)
		{
			sub(div, bediv, temp);
			div = temp;
			add(result, ter, temp);
			result = temp;
		}
	}
	//计算符号位
	num1.sign = sign1;
	num2.sign = sign2;
	if (result.len == 0)
		result.sign = 0;
	else
		result.sign = sign1 ^ sign2;
	return;
}



void mod(bignum& num1, bignum& num2, bignum& result)
{
	bignum temp, div, bediv;
	bignum one(1), ter, ten(10);
	result.sign = 0;
	int i;
	for (i = 0; i < 79; i++)
		result.array[i] = 0;
	result.len = 0;
	int sign1 = num1.sign;
	int sign2 = num2.sign;
	num1.sign = 0;
	num2.sign = 0;

	div = num1;
	if (div.sign == 1)
	{
		while (div < num2)
		{
			add(div, num2, temp);
			div = temp;
		}
	}
	while (num2 <= div)
	{
		bediv = num2;
		ter = one;
		while (bediv < div)
		{
			mul(bediv, ten, temp);
			if (div < temp)
			{
				break;
			}
			bediv = temp;
			mul(ter, ten, temp);
			ter = temp;
		}
		while (bediv <= div)
		{
			sub(div, bediv, temp);
			div = temp;
		}
	}
	result = div;

	num1.sign = sign1;
	num2.sign = sign2;
	if (result.len == 0)
		result.sign = 0;
	else
		result.sign = sign1;
	return;
}



istream& operator>>(istream& input, bignum& num)
{
	char str1[400], s;
	int str2[300];
	int i, len = 0;
	for (i = 0; i < 300; i++)
	{
		str2[i] = 0;
	}
	input >> str1;
	for (i = 0; i < 400 && str1[i] != '#'; i++)
	{
	}
	len = i;
	if (str1[0] == '-')//为负数
	{
		len--;
		for (i = 0; i < len; i++)
		{
			str2[i] = str1[len - i] - 48;
		}
		num.sign = 1;
	}
	else//为正数或0
	{
		for (i = 0; i < len; i++)
		{
			str2[i] = str1[len - i - 1] - 48;
		}
		num.sign = 0;
	}
	for (i = 0; i < len; i++)
	{
		num.array[i / 4] += str2[i] * pow(10, i % 4);
	}
	num.len = (len - 1) / 4 + 1;
	len = 0;
	for (i = 0; i < num.len; i++)
	{
		if (num.array[i] != 0)
		{
			len = 1;
			break;
		}
	}
	if (len == 0)
	{
		num.len = 0;
	}
	return input;
}



ostream& operator<<(ostream& output, bignum& num)
{
	int i;
	if (num.sign == 1)
	{
		output << '-';
	}
	if (num.len == 0)
	{
		output << 0 << '#' << endl;
	}
	else
	{
		if (num.len == 1)
		{
			output << num.array[0];
		}
		else
		{
			output << num.array[num.len - 1];
			for (i = num.len - 2; i >= 0; i--)
			{
				output.fill('0');
				output.width(4);
				output.setf(ios::right);
				output << num.array[i];
			}
		}
		cout << '#' << endl;
	}
	return output;
}



bool bignum::operator<(bignum& num2)
{
	int i, flag;
	if (len == num2.len && len == 0)
	{
		return false;
	}
	if (sign > num2.sign)//num1<0,num2>0
	{
		return true;
	}
	else
	{
		if (sign == num2.sign)//num1,num2同号
		{
			if (sign == 1)//num1,num2同为负数
			{
				if (len > num2.len)//num1位数多
				{
					return true;
				}
				else
				{
					if (len == num2.len)//位数相同
					{
						for (i = 79; i >= 0; i--)//num1<num2
						{
							if (array[i] > num2.array[i])
							{
								return true;
							}
						}
						return false;
					}
					else
					{
						return false;
					}
				}
			}
			else//正数
			{
				if (len < num2.len)//num1位数少
				{
					return true;
				}
				else
				{
					if (len == num2.len)//位数相同
					{
						for (i = 79; i >= 0; i--)//num1<num2
						{
							if (array[i] < num2.array[i])
							{
								return true;
							}
						}
						return false;
					}
					else
					{
						return false;
					}
				}
			}
		}
		else
		{
			return false;
		}
	}
}



bool bignum::operator<=(bignum& num2)
{
	int i;
	if (len == num2.len && len == 0)
	{
		return true;
	}
	if ((*this) < num2)
	{
		return true;
	}
	else
	{
		if (sign == num2.sign)
		{
			if (len == num2.len)
			{
				for (i = 0; i < len; i++)
				{
					if (array[i] != num2.array[i])
					{
						return false;
					}
				}
				return true;
			}
			else
			{
				return false;
			}
		}
		else
		{
			return false;
		}
	}
}



bignum& bignum::operator=(bignum& num)
{
	len = num.len;
	sign = num.sign;
	int i;
	for (i = 0; i < 80; i++)
	{
		array[i] = num.array[i];
	}

	return *this;
}


/*
bignum bignum::square()
{
	bignum result,one(1),result2,two(2);
	result = (*this) / two;
	result2 = result + one;
	bignum temp;

	while (result * result <= (*this) && (*this) < temp)
	{
		result = (*this) + result;
		result = result / two;
		result2 = result + one;
		temp = result2 * result2;
	}
	return result;
}
*/

/*
void sieve(bignum& num,ifstream& input, ofstream& output)
{
	bignum zero(0),one(1),two(2),three(3);
	bignum n=num.square();
	bignum pnum;
	int flag;
	if (n <= two&&two<=n)
	{
		return;
	}
	if (n <= three && three <= n)
	{
		return;
	}
	sieve(n,input,output);
	n = n + one;
	while (n <= num)
	{
		flag = 0;
		while (input >> pnum)
		{
			if (n % pnum <= zero)//能整除
			{
				flag = 1;
				break;
			}
			else//不能整除
			{
				continue;
			}
		}
		if (flag == 0)
		{
			output << n;
		}
		input.close();
		input.open("numbertable.txt", ios::in);
	}
}
*/

bool judgemod(bignum& num1, bignum& num2)
{
	bignum result;
	mod(num1, num2, result);
	if (result.len == 0)
	{
		return true;
	}
	else
		return false;
}

void get_div_mod(bignum& num1, bignum& num2)
{
	bignum result;
	div(num1, num2, result);
	cout << "商是：" << result;
	mod(num1, num2, result);
	cout << "余数是：" << result;
}

void cal_ggo(bignum& num1, bignum& num2,bignum& result)
{
	bignum temp1, temp2;
	temp1 = num1;
	temp2 = num2;
	mod(temp1, temp2, result);
	if (result.len == 0)
	{
		result = temp2;
		return;
	}
	else
	{
		temp1 = temp2;
		temp2 = result;
		mod(temp1, temp2, result);
	}

}
void bezout(bignum& num1, bignum& num2, bignum& s, bignum& t)
{
	int flag=0;
	bignum r_2(num1), r_1(num2), s_2(1), s_1(0), t_2(0), t_1(1),zero(0),q,temp,result;
	if (r_1 <= zero && zero <= r_1)
	{
		s = s_2;
		t = t_2;
		return;
	}
	else
	{
		div(r_2, r_1, q);
		q = contrary(q);
		mul(q, r_1, temp);
		add(temp, r_2, result);
		r_2 = result;
	}
	while (1)
	{
		if (flag == 1)
		{
			if (r_1 <= zero && zero <= r_1)
			{
				s = s_2;
				t = t_2;
				return;
			}
			else
			{
				mul(q, s_2, temp);
				add(temp, s_1, result);
				s_1 = result;

				mul(q, t_2, temp);
				add(temp, t_1, result);
				t_1 = result;

				div(r_2, r_1, q);
				q = contrary(q);
				mul(q, r_1, temp);
				add(temp, r_2, result);
				r_2 = result;
				flag = 1;
			}
		}
		else
		{
			if (r_2 <= zero && zero <= r_2)
			{
				s = s_1;
				t = t_1;
				return;
			}
			else
			{
				mul(q, s_1, temp);
				add(temp, s_2, result);
				s_2 = result;

				mul(q, t_1, temp);
				add(temp, t_2, result);
				t_2 = result;

				div(r_1, r_2, q);
				q = contrary(q);
				mul(q, r_2, temp);
				add(temp, r_1, result);
				r_1 = result;
				flag = 1;
			}
		}
	}
}

void mod_repeat_square(bignum& b, bignum& n, bignum& m,bignum& result)
{
	bignum n1=n, b0;
	bignum temp;
	//模平方计算法对a,b0进行初始化
	result = temp;
	mod(b, m, b0);

	int bin_form[1000],i,j;
	for (i = 0; i < 1000; i++)
		bin_form[i] = 0;
	bignum two(2);
	//将指数n转化为二进制的形式
	i = 0;
	while (n1.len != 0)
	{
		mod(n1, two, temp);
		if (temp.len == 1)
		{
			bin_form[i] = 1;
			i++;
		}
		div(n1, two, temp);
		n1 = temp;
	}

	//模平方计算法
	for (j = 0; j < i; j++)
	{
		if (bin_form[j] == 1)
		{
			mul(result, b0, temp);
			mod(temp, m, result);
			mul(b0, b0, temp);
			b0 = temp;
		}
		else
		{
			mul(b0, b0, temp);
			b0 = temp;
		}
	}
}

void diffie_hellman(bignum& p, bignum& g,bignum& R1 , bignum& R2, bignum& y,bignum& k)
{
	mod_repeat_square(R1, y, p, k);
	mod_repeat_square(g, y, p, R2);
}

void CRT(bignum& x, bignum& b, bignum& m, bignum& N, bignum& result)
{
	bignum N2,no_use,M,temp;
	bezout(N, m, N2, no_use);
	mul(N, m, M);
	sub(b, x, temp);
	mod(temp, m, result);
	mul(N, result, temp);
	mod(temp, M, result);
	mul(N2, result, temp);
	mod(temp, M, result);
	add(x, result, temp);
	mod(temp, M, result);
	return;
}

void Fermat_Check(bignum& n, bignum& t)
{
	bignum base(2),temp,one(1),result,flag;
	flag = t;
	while (flag.len != 0)
	{
		cal_ggo(n, base, temp);
		if(temp<=one&&one<=temp)
		{
			sub(n, one, temp);
			mod_repeat_square(base, temp, n, result);
			if (result <= one && one <= result)
			{
				//是以base为基的伪素数
				sub(flag, one, temp);
				flag = temp;
				continue;
			}
			else
			{
				cout << "该数是合数。" << endl;
				return;
			}
		}
		else
		{
			cout << "该数是合数。" << endl;
			return;
		}
	}
	cout << "n是合数的可能性小于1/2的" << t << "次方" << endl;
	return;
}