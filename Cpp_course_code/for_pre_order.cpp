//According to the post order and in order,count the pre order of a binary tree
#include<iostream>
using namespace std;
char post[100], in[100];
void fun(int pleft,int pright,int ileft,int iright);
int main()
{
	int len,i;
	cin >> in;
	cin >> post;
	for(i=0;post[i]!='\0';i++)
	{ }
	len = i-1;
	fun(0, len, 0, len);
	cout << endl;
}
void fun(int pleft, int pright, int ileft, int iright)
{
	if(pright<pleft)
	{
		return;
	}
	int i;
	cout << post[pright];//后序的最后一个必定是root
	for (i = ileft; in[i] != post[pright]; i++)//找到inorder中对应的root
	{}
	fun(pleft, pright - iright + i - 1, ileft, i - 1);
	fun(pright - iright + i, pright - 1, i + 1, iright);
}