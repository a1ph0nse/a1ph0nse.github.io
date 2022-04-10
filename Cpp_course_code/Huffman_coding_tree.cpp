//an example of Huffman coding tree
#include<iostream>
using namespace std;
class str
{
public:
	char s;
	int weight,depth;
	str* left;
	str* right;
	str();
	str(int w,str*l,str*r);
	~str();
};
str::str()
{
	s = '\0';
	weight = 0;
	depth = 0;
	left = NULL;
	right = NULL;
}
str::str(int w, str* l, str* r)
{
	s = '\0';
	weight = w;
	left = l;
	right = r;
	depth = 0;
}
str::~str()
{
	s = '\0';
	weight = 0;
	depth = 0;
	left = NULL;
	right = NULL;
}

void Sort(str*word,int head,int tail);
void change(str* word, int i1, int i2);
void build(str* word, int& head, int& tail);
void caldepth(str source,int[]);
int main()
{
	int test;
	while (cin >> test)
	{
		int counter;
		int num,i,j,head,tail;
		char text[100];
		char s;
		str* word;
		int* leaf;
		int result;
		for (counter = 0; counter < test; counter++)
		{
			cin >> num;
			word = new str[2 * num - 1];
			for (i = 0; i < num; i++)
			{
				cin >> s >> j;
				word[i].s = s;
				word[i].weight = j;
			}
			cin >> text;
			head = 0;
			tail = num - 1;
			build(word, head, tail);
			leaf = new int[num];
			caldepth(word[tail],leaf);
			result = 0;
			for (i = 0; text[i] != '\0'; i++) 
			{
				j = text[i] - 65;
				result += leaf[j];
			}
			cout << result << endl;
			delete []word;
		}
	}
}
void Sort(str* word, int head, int tail)
{
	int i,j,n=tail-head+1;
	for (i = 0; i < n-1; i++)
	{
		for (j = i+1; j < n; j++)
		{
			if (word[i+head].weight > word[j+head].weight)
			{
				change(word, i+head, j+head);
			}
		}
	}
}
void change(str* word, int i1, int i2)
{
	str temp;
	temp = word[i1];
	word[i1] = word[i2];
	word[i2] = temp;
}
void build(str* word, int& head, int& tail)
{
	if (head==tail)
		return;
	Sort(word, head, tail);
	tail++;
	word[tail].weight = word[head].weight + word[head + 1].weight;
	word[tail].left= &word[head];
	word[tail].right= &word[head+1];
	head += 2;
	build(word, head, tail);
}
void caldepth(str source,int* leaf)
{
	if (source.left != NULL)
	{
		source.left->depth = source.depth + 1;
		caldepth(*(source.left),leaf);
	}
	if (source.right != NULL)
	{
		source.right->depth = source.depth + 1;
		caldepth(*(source.right),leaf);
	}
	else
	{
		leaf[source.s - 65] = source.depth;
	}
}
