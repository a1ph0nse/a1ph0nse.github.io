//usage of template
#include<iostream>
#include<iomanip>
using namespace std;
template<typename T>
void get_average(T*, int);
int main()
{
	int flag, n,i;
	while (cin >> flag)
	{
		if (!flag)
		{
			cin >> n;
			int* array = new int[n];
			for (i = 0; i < n; i++)
			{
				cin >> array[i];
			}
			get_average(array, n);
		}
		else
		{
			cin >> n;
			double* array = new double[n];
			for (i = 0; i < n; i++)
			{
				cin >> array[i];
			}
			get_average(array, n);
		}
	}
}
template<typename T>
void get_average(T* array, int n)
{
	T sum=0;
	int i;
	for (i = 0; i < n; i++)
	{
		sum += array[i];
	}
	cout<<fixed<<setprecision(2)<< sum / n << endl;
}