//an example of Toposort but there are some bug in the code
#include<iostream>
using namespace std;
class edge
{
public:
	int index;
	edge* next;
	edge();
};
edge::edge()
{
	index = -1;
	next = NULL;
}
class vertex
{
public:
	int head;
	edge* next;
	vertex();
};
vertex::vertex()
{
	head = -1;
	next = NULL;
}


void TopoSort(vertex* v, int* indeg, int* queue,int&head,int&tail,int num);
void  cal_indeg(vertex* v, int* indeg,int num);
void inqueue(int* queue, int& head, int& tail, int num);
void dequeue(int* queue, int& head, int& tail);
bool check(vertex* v, int num);
int main()
{
	int num;
	while (cin >> num)
	{
		int i;
		char s;
		vertex* v;
		edge* e1,*e2,*h;
		v = new vertex[num];
		int* indeg = new int[num+10];
		for (i = 0; i < num; i++)
		{
			indeg[i] = 0;
		}
		int* queue = new int[num];
		int head, tail;
		for (i = 0; i < num; i++)
		{
			cin >> s;
			e2 = NULL;
			h = NULL;
			if (s == '[')
			{
				cin >> v[i].head;
				h = new edge;
			}
			if (s != ']')
			{
				cin >> h->index;
				e2 = h->next;
				cin >> s;
			}
			while (s != ']')
			{
				e1= new edge;
				e2->index = s - 48;
				e2->next = e1;
				e2 = e2->next;
				cin >> s;
			}
			v[i].next = h;
		}
		head = 0;
		tail = 0;
		cal_indeg(v, indeg, num);
		cout << "[";
		TopoSort(v, indeg, queue, head, tail,num);
		cout << "]\n";
	}
}
void cal_indeg(vertex* v, int* indeg,int num)
{
	int i;
	edge* p;
	for (i = 0; i<num; i++)
	{
		if (v[i].head == -1)
		{
			continue;
		}
		p = v[i].next;
		while (p->index>=0&&p->index<num)
		{
			indeg[p->index]++;
			p = p->next;
		}
	}
}
void inqueue(int* queue, int& head, int& tail,int num)
{
	queue[tail] = num;
	tail++;
}
void dequeue(int* queue, int& head, int& tail)
{
	head++;
}
void TopoSort(vertex* v, int* indeg, int* queue, int& head, int& tail, int num)
{
	int i,n;
	edge* e;
	for (i = 0; i < num; i++)
	{
		if (indeg[i] == 0)
		{
			inqueue(queue, head, tail, i);
			indeg[i] = -1;
		}
	}
	n = queue[head];
	e = v[n].next;
	while (e != NULL&&e->index!=-1)
	{
		indeg[e->index]--;
		e = e->next;
	}
	v[n].head = -1;
	cout <<" " << n;
	dequeue(queue, head, tail);
	if (check(v,num))
	{
		TopoSort(v, indeg, queue, head, tail, num);
	}
	else
	{
		return;
	}
}
bool check(vertex*v, int num)
{
	int i,flag=0;
	for (i = 0; i < num; i++)
	{
		if (v[i].head != -1)
		{
			flag = 1;
			break;
		}
	}
	if (flag == 1)
	{
		return true;
	}
	else
	{
		return false;
	}
}
