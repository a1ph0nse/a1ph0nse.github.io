//a small maze game
#include<iostream>
#include<cstdlib>
#include<ctime>
using namespace std;
void mazeGenerator(char**&,int,int);    //迷宫生成
void mazeTraverse(char**&,int,int,int,int,int,int);             //走迷宫
void entrance(char**&, int, int);          //生成入口
void exit(char**&, int, int);              //生成出口
void display(char**, int, int);                   //显示迷宫
int finden(char**, int);                    //找到入口位置
int dir(int, int, int, int);                //确定人的朝向
int main()
{
	cout << "请输入迷宫的长和宽(中间用空格分开):";              //长是横，宽是竖，构造出list[width][length]
	int length,width,i,enterw;
	cin >> length >> width;
	char** maze = new char* [width];
	for (i = 0; i < width; i++)
	{
		maze[i] = new char[length];
	}
	mazeGenerator(maze,width, length);          //创建迷宫
	enterw=finden(maze, width);                 //入口的w坐标
	display(maze, width, length);               //显示迷宫（入口已标记）
	cout << endl;
	cout << "Hit return to continue:" << endl;
	while(1)
	{
		if (cin.get() == '\n')
			break;
	}
	mazeTraverse(maze, width, length,enterw,1,enterw-1,1);          //走迷宫,此处为入口右边的第一个点
}
void mazeGenerator(char**&pa,int w, int l)//w是宽，l是长,生成迷宫
{
	int j, k,random;
	srand(int(time(0)));
	for (j=1; j < w-1; j++)            //先生成内部
	{
		for (k=1; k <l-1; k++)
		{
			random = rand() % 100 + 1;
			if (random<=70)
			{
				pa[j][k] = '.';
			}
			else
			{
				pa[j][k] = '#';
			}
		}
	}
	for (j = 0; j < l; j++)       //补充上下的墙
	{
		pa[0][j] = '#';
		pa[w - 1][j] = '#';
	}
	for (j = 0; j < w; j++)       //补充左右的墙
	{
		pa[j][0]='#';
		pa[j][l - 1] = '#';
	}
	entrance(pa, w, l);          //递归加入入口
	exit(pa, w, l);              //递归加入出口
}
void entrance(char**& ma, int w, int l) //递归加入入口
{
	int i,flag = 0;
	static int en=0;
	for (i = 1; i < w - 1; i++)
	{
		if (ma[i][en+1] == '.')
		{
			ma[i][en] = '.';
			flag++;
			en--;
			break;
		}	
	}
	if (flag == 0)
	{
		en++;
		entrance(ma, w, l);
		entrance(ma, w, l);
	}
}
void exit(char**& ma, int w, int l)     //递归加入出口
{
	int i, flag = 0;
	static int ex = l-1;
	for (i = 1; i < w - 1; i++)
	{
		if (ma[i][ex-1] == '.')
		{
			ma[i][ex] = '.';
			flag++;
			ex++;
			break;
		}
	}
	if (flag == 0)
	{
		ex--;
		exit(ma, w, l);
		exit(ma, w, l);
	}
}
void mazeTraverse(char**& maze,int w,int l,int manw,int manl,int handw,int handl)  //走迷宫,hand为手摸着的墙壁（下面简称手），man为人所在的位置
{
	while (1)
	{
		if(cin.get()=='\n')
		{
			break;
		}
	}
	int face;
	if (manl == l-1||manl==0)
	{
		if (manl == l-1)
		{
			maze[manw][manl] = 'X';
			display(maze, w, l);
			cout << endl << "成功走出迷宫" << endl;
			return;
		}
		else
		{
			display(maze, w, l);
			cout << endl << "回退到入口" << endl;
			return;
		}
	}
	else
	{
		maze[manw][manl] = 'X';
		display(maze, w, l);
		cout << endl;
		cout << "Hit return to continue:" << endl;
		if(maze[handw][handl]!='#')                             //当左手摸不到墙壁的时候，移动直到摸到墙壁
		{
			face = dir(manw, manl, handw, handl);
			switch (face)
			{
			case 1:
			{
				manw--;
				handw = manw;
				handl = manl - 1;
				mazeTraverse(maze, w, l, manw, manl, handw, handl);
				break;
			}
			case 2:
			{
				manw++;
				handw = manw;
				handl = manl + 1;
				mazeTraverse(maze, w, l, manw, manl, handw, handl);
				break;
			}
			case 3:
			{
				manl--;
				handl = manl;
				handw = manw + 1;
				mazeTraverse(maze, w, l, manw, manl, handw, handl);
				break;
			}




			case 4:
			{
				manl++;
				handl = manl;
				handw = manw - 1;
				mazeTraverse(maze, w, l, manw, manl, handw, handl);
				break;
			}
			}
		}
		else
		{
			face = dir(manw, manl, handw, handl);
			switch (face)
			{
			 case 1:
			 {
				 if(maze[manw][manl+1]!='#')
				 {
					 manl++;
					 handl++;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
				 else
				 {
					 handw = manw;
					 handl = manl + 1;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
			 }
			 case 2:
			 {
				 if(maze[manw][manl-1]!='#')                            //前方有路就走
				 {
					 manl--;
					 handl--;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
				 else                                                  //前方没路就转弯
				 {
					 handw = manw;
					 handl = manl - 1;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
			 }
			 case 3:
			 {
				 if (maze[manw-1][manl] != '#')                            //前方有路就走
				 {
					 manw--;
					 handw--;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
				 else                                                  //前方没路就转弯
				 {
					 handl = manl;
					 handw = manw - 1;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
			 }
			 case 4:
			 {
				 if (maze[manw + 1][manl] != '#')                            //前方有路就走
				 {
					 manw++;
					 handw++;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
				 else                                                  //前方没路就转弯
				 {
					 handl = manl;
					 handw = manw + 1;
					 mazeTraverse(maze, w, l, manw, manl, handw, handl);
					 break;
				 }
			 }
			}
		}
	}
}
void display(char** maze, int w, int l)         //显示当前迷宫
{
	int i, j;
	for (i = 0; i < w; i++)
	{
		for (j = 0; j < l; j++)
		{
			cout << maze[i][j]<<" ";
		}
		cout << endl;
	}
}
int finden(char** maze, int w)            //找到迷宫入口
{
	int i;                                        //i是入口的w坐标
	for (i = 1; i < w - 1; i++)                   //找入口
	{
		if (maze[i][0] == '.')
		{
			maze[i][0] = 'X';                     //标记入口
			break;
		}
	}
	return i;                                     //返回入口的w坐标
}
int dir(int manw, int manl, int handw, int handl)  //确定人的朝向,1代表面向右边，2代表左边，3代表上边，4代表下边
{
	if (manw > handw && manl == handl)
	{
		return 1;
	}
	else
	{
		if (manw < handw && manl == handl)
		{
			return 2;
		}
		else
		{
			if (manw == handw && manl > handl)
			{
				return 3;
			}
			else
			{
				return 4;
			}
		}
	}
}