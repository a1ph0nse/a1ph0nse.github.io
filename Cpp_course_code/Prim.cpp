// classic Prim
#include<iostream>
using namespace std;

void Prim(int** graph, int* set, int n);
bool in_set(int* set, int v);
void find_edge(int** graph, int* set, int& v1, int& v2,int n);
bool end(int* set,int n);
int main()
{
	int n, e,v1,v2;
	int** graph;
	int i,j;
	while (cin >> n >> e)
	{
		//建立图，输入权重，没有的边权重为0
		graph = new int* [n];
		for (i = 0; i < n; i++)
		{
			graph[i] = new int[n];
			for (j = 0; j < n; j++)
			{
				graph[i][j] = 0;
			}
		}
		for (i = 0; i < e; i++)
		{
			cin >> v1>> v2;
			cin >> graph[v1 - 1][v2 - 1];
		}
		//Prim算法构造最小生成树
		int* set;
		set = new int[n];//记录顶点是否被选取的集合，入选为1，否则为0
		for (i = 0; i < n; i++)
		{
			set[i] = 0;
		}
		set[0] = 1;//让0入选
		Prim(graph, set, n);
	}
}
void Prim(int** graph, int* set, int n)
{
	int v1, v2,result=0;
	while (!end(set, n))
	{
		find_edge(graph, set, v1, v2,n);
		result += graph[v1][v2];
		set[v1] = 1;
		set[v2] = 1;
	}
	cout << result << endl;
	return;
}
bool in_set(int* set, int v)
{
	if (set[v] == 1)
		return true;
	else
		return false;
}
void find_edge(int** graph, int* set, int& v1, int& v2,int n)
{
	int i, j;
	v1 = 0;
	v2 = 0;
	for (i = 1; i < n; i++)
	{
		for (j = 0; j < i; j++)
		{
			if ((in_set(set, i) && !in_set(set, j)) || (in_set(set, j) && !in_set(set, i)))
			{
				if (graph[v1][v2] == 0 || (graph[v1][v2] > graph[i][j] && graph[i][j] > 0))
				{
					v1 = i;
					v2 = j;
				}
			}
		}
	}
}
bool end(int* set,int n)//没结束返回false,否则返回true
{
	int i;
	for (i = 0; i < n; i++)
	{
		if (set[i] == 0)
			return false;
	}
	return true;
}