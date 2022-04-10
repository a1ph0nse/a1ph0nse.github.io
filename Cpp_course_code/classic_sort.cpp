//include select sort,bubble sort,heap sort,merge sort,quick sort
#include<iostream>
#include<cmath>
using namespace std;
void csort(int* array, int len,int& flag);
void bsort(int* array, int len, int& flag);
void hsort(int* array, int len, int& flag);
void msort(int* array,int*& temp, int left,int right, int& flag);
void qsort(int* array, int left,int right, int& flag);
void change(int* array, int sign1, int sign2);
void Down(int* array, int k, int len,int& flag);
void buildheap(int* array, int len,int& flag);
int main()
{
	int i, len, way,flag=0;
	while (cin >> len >> way)
	{
		int* array = new int[len];
		int* temp = new int[len];
		for (i = 0; i < len; i++)
		{
			cin >> array[i];
		}
		switch (way)
		{
		case 1:csort(array, len, flag); break;
		case 2:bsort(array, len, flag); break;
		case 3:hsort(array, len, flag); break;
		case 4:msort(array,temp, 0,len-1, flag); break;
		case 5:qsort(array,0, len-1, flag); break;
		}
		for (i = 0; i < len-1; i++)
		{
		cout << array[i] << " ";
		}
		cout << array[i];
		cout << endl;
		cout << flag << endl;
		flag = 0;
	}

}
void csort(int* array, int len, int& flag)
{
	int i,j;
	for (i = 0; i < len; i++)
	{
		for (j = i+1; j < len; j++)
		{
			if (array[i] > array[j])
			{
				change(array, i, j);
			}
				flag++;
		}
	}

}
void bsort(int* array, int len, int& flag)
{
	int i, j,work;
	for (i = 0; i < len; i++)
	{
		work = 1;
		for (j = 0; j < len-i-1; j++)
		{
			if (array[j] > array[j + 1])
			{
				change(array, j, j + 1);
				work = 0;
			}
			flag++;
		}
		if (work)
			break;
	}
}
void hsort(int* array, int len, int& flag)
{
	int i, j;
	buildheap(array, len,flag);
	for (i = len - 1; i > 0; i--)
	{
		change(array, 0, i);
		Down(array, 0, i,flag);
	}
}
void buildheap(int* array, int len,int&flag)
{
	int k = len / 2 - 1;
	for (; k >= 0; k--)
	{
		Down(array, k, len,flag);
	}
}
void Down(int* array, int k, int len,int&flag)
{
	int p, c;
	p = k;
	c = 2 * k + 1;
	while (c < len)
	{
		if (c + 1 < len && array[c] < array[c + 1])
		{
			c++;
		}
		if (array[p] < array[c])
		{
			change(array, p, c);
			p = c;
		}
		flag++;
		c = c * 2 + 1;
	}
}
void msort(int* array,int*& temp,int left, int right, int& flag)
{
	int i;
	if (left == right)
		return;
	int mid = (left + right) / 2;
	msort(array, temp, left, mid,flag);
	msort(array,temp, mid+1, right,flag);
	for (i = left; i <= right; i++)
	{
		temp[i] = array[i];
	}
	int i1 = left;
	int i2 = mid + 1;
	for (i = left; i1<=mid&&i2 <= right;)
	{

		if (temp[i1] <= temp[i2])
		{
			array[i++] = temp[i1++];
		}
		else
		{
			array[i++] = temp[i2++];
		}
		flag++;
	}
	while (i1 <= mid)
		array[i++] = temp[i1++];
	while (i2 <= right)
		array[i++] = temp[i2++];
	for (i = left; i <= right; i++)
		temp[i] = array[i];
}
void qsort(int* array, int left,int right,int& flag)
{
	int i,last;
	if (left < right)
	{
		last = left;
		for (i = left + 1; i <= right; i++)
		{
			if (array[i] < array[left])
			{
				change(array, ++last, i);
			}
			flag++;
		}
		change(array, left, last);
		qsort(array, left, last - 1, flag);
		qsort(array, last + 1, right, flag);
	}
}
void change(int* array, int sign1, int sign2)
{
	int temp;
	temp=array[sign1];
	array[sign1] = array[sign2];
	 array[sign2] =temp;
}