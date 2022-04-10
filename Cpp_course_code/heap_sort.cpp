//a small example of heap sort
#include<iostream>
using namespace std;
void hsort(int* array, int len);
void change(int* array, int sign1, int sign2);
void buildheap(int* array, int len);
void Down(int* array, int k, int len);
int main()
{
	int i,len;
	int pa[1000];
	for (i = 0;cin >> pa[i]; i++)
	{}
	len = i;
	hsort(pa, len);
}
void hsort(int* array, int len)
{
	int i,j;
	buildheap(array, len);
	for (j = 0; j < len; j++)
	{
		cout << array[j] << " ";
	}
	cout << endl;
	for (i = len - 1; i > 0; i--)
	{
		change(array, 0, i);
		
		Down(array, 0, i);
	}
	for (j = 0; j < len; j++)
	{
	cout << array[j] << " ";
	}
	cout << endl;
}
void buildheap(int* array, int len)
{
	int k = len / 2 - 1;	
	for (; k >= 0; k--)
	{
		Down(array, k, len);
	}
}
void Down(int* array, int k, int len)
{
	int p, c;
	p = k;
	c = 2 * k + 1;
	while (c < len)
	{
		if (c + 1 < len && array[c] > array[c + 1])
		{
			c++;
		}
		if (array[p] > array[c])
		{
			change(array, p, c);
			p = c;
		}
		c = c * 2 + 1;
	}
}
void change(int* array, int sign1, int sign2)
{
	int temp;
	temp = array[sign1];
	array[sign1] = array[sign2];
	array[sign2] = temp;
}