//classic BFS
#include<iostream>
using namespace std;
class graph
{
public:
	int** e;
	int Vnum;
	int Enum;
	int source;
	graph(int V, int E, int S);
	graph();
	~graph();
};
graph::graph(int V, int E, int S)
{
	Vnum = V;
	Enum = E;
	source = S;
	e = new int*[V];
	int i;
	for (i = 0; i < V; i++)
	{
		e[i] = new int[V];
	}
	int j;
	for (i = 0, j = 0; i < V; i++)
	{
		for (j = 0; j < V; j++)
		{
			e[i][j] = 0;
		}
	}
}
graph::graph()
{
	Vnum = 0;
	Enum = 0;
	source = 0;
	e = NULL;
}
graph::~graph()
{
	Vnum = 0;
	Enum = 0;
	source = 0;
	delete e;
	e = NULL;
}

void setmark(int* mark,int index);
void inqueue(int* queue, int num, int& tail);
void dequeue(int* queue,int& head);
void BFS(int* queue, int* mark, graph* g, int& head, int& tail,int& s);
void BFS(int* queue, int* mark, graph* g, int& head, int& tail,int& s);
int main()
{
	int test;
	int n, e, s,e1,e2,i;
	cin >> test;
	int* mark;
	int* queue;
	graph* g;
	int head, tail;
	for (; test > 0; test--)
	{
		cin >> n >> e >> s;
		mark = new int[n];
		g= new graph(n,e,s);
		i = 0;
		for (i=0;i<e;i++)
		{
			cin >> e1 >> e2;
			g->e[e1][e2] = 1;
			g->e[e2][e1] = 1;
		}
		queue = new int[n+1];
		for (i = 0; i < n; i++)
		{
			queue[i] = -1;
			mark[i] = 0;
		}
		head = 0;
		tail = 0;	
		inqueue(queue, s, tail);
		setmark(mark, s);
		BFS(queue, mark, g, head, tail,s);
		for (i = 0; i < n-1; i++)
		{
			cout << queue[i] << " ";
		}
		cout << queue[i] << endl;
	}
}
void setmark(int* mark, int index)
{
	mark[index] = 1;
}
void inqueue(int* queue, int num, int& tail)
{
	queue[tail] = num;
	tail++;
}
void dequeue(int* queue, int& head)
{
	head++;
}
void BFS(int* queue, int* mark, graph* g,int& head,int&tail,int& s)
{
	if (head == tail && head != 0)
	{
		return;
	}
	dequeue(queue, head);
	int i;
	for (i = 0; i < g->Vnum; i++)
	{
		if (g->e[s][i] == 1&&mark[i]==0)
		{
			inqueue(queue, i, tail);
			setmark(mark, i);
		}
	}
	BFS(queue, mark, g, head, tail, queue[head]);
}