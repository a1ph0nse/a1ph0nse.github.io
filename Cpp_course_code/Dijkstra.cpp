//classic Dijkstra
#include<iostream>
using namespace std;

void Dijkstra(int** graph, int* set, int* distance, int n, int s, int t);
//void find_edge(int** graph, int* set, int& v1, int& v2, int n);
bool in_set(int* set, int v);
bool end(int* set, int n);
int main()
{
	int n, c, s, t;
	int i, j,v1,v2,w;
	int** graph;
	int* set;
	int* distance;
	while (cin >> n >> c >> s >> t)
	{
		s--;
		t--;
		graph = new int* [n];
		for (i = 0; i < n; i++)
		{
			graph[i] = new int[n];
			for (j = 0; j < n; j++)
			{
				graph[i][j] = 0;
			}
		}
		for (i = 0; i < c; i++)
		{
			cin >> v1 >> v2;
			cin >> w;
			if (graph[v1 - 1][v2 - 1] == 0 ||( w < graph[v1 - 1][v2 - 1]&& graph[v1 - 1][v2 - 1] != 0))
			{
				graph[v1 - 1][v2 - 1] = w;
				graph[v2 - 1][v1 - 1] = w;
			}
		}
		//初始化图完成
		set = new int[n];
		for (i = 0; i < n; i++)
		{
			set[i] = 0;
		}
		set[s] = 1;
		//0表示不在set中，1表示在set中
		distance = new int[n];
		for (i = 0; i < n; i++)
		{
			distance[i] = 0;
		}
		for (i = 0; i < n; i++)
		{
			distance[i] = graph[s][i];
		}
		//0表示距离无限大
		Dijkstra(graph, set, distance, n, s, t);
	}
	
}
void Dijkstra(int** graph, int* set, int* distance, int n, int s, int t)
{
	int i, j, min,minpoint=s;
	while (!end(set, n)) 
	{
		for (i = 0,min=0; i < n; i++)
		{
			if(!in_set(set,i))
			{
				if ((distance[i] != 0 && min > distance[i]) || min == 0)
				{
					min = distance[i];
					minpoint = i;
				}
			}
		}
		set[minpoint] = 1;
		//找到当前最小的点及其w
		for (i = 0; i < n; i++)
		{
			if (!in_set(set,i)&& graph[minpoint][i]!=0)
			{
				if(distance[i]==0|| distance[i] > min + graph[minpoint][i])
					distance[i] = min + graph[minpoint][i];
			}
		}
	}
	cout << distance[t] << endl;
}

bool in_set(int* set, int v)
{
	if (set[v] == 1)
		return true;
	else
		return false;
}
bool end(int* set, int n)//没结束返回false,否则返回true
{
	int i;
	for (i = 0; i < n; i++)
	{
		if (set[i] == 0)
			return false;
	}
	return true;
}