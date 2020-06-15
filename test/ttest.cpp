#include <typeinfo>
#include <emp-tool/emp-tool.h>
#include "ESwap/ESwap.h"
using namespace emp;
using namespace std;


int port, party;
NetIO * io;


Bit inner(void* ctx){
	int n=100000;
	Number sum=0;
	Bit bit(true,PROVER);
	for(int i=0;i<n;i++){
		Number a(BITLENGTH,i,PROVER);
		Number b(BITLENGTH,1,VERIFIER);
		sum=sum+a*b;
	}
	Number t=4900;
	bit=sum>t;
	return bit;
} 

Bit ed(void* ctx){
	int n=100;
	
	
	int seed=111;
	auto rnd=[&seed]{return seed=(seed*2411+12412)%10007;};

	Bit bit(true,PROVER);
	Number dp[101][101];


	for(int i=0;i<=n;i++){
		dp[i][0]=Number();
		dp[0][i]=Number();
	}

	for(int i=1;i<=n;i++)
	for(int j=1;j<=n;j++){
		Bit t=dp[i][j-1] <= dp[i-1][j];
		dp[i][j]=dp[i][j-1].select(t,dp[i-1][j]);
		Number s=rnd()%5;
		Bit t2=dp[i][j] <= dp[i-1][j-1]+s;
		dp[i][j]=dp[i][j].select(t2,dp[i-1][j-1]+s);

	}
	
	return bit;
} 


Bit fac(void* ctx){
	int n=100000;
	
	int seed=111;
	auto rnd=[&seed]{return seed=(seed*2411+12412)%10007;};

	Bit bit(true,PROVER); 

	for(int i=0;i<n;i++){

		int x,y,z;
		x=rnd()%1000;
		y=rnd()%1000;
		z=x*y;
		Number a=Number(BITLENGTH,x,PROVER);
		Number b=Number(BITLENGTH,y,PROVER);
		Number c=z;

		bit = bit &(a*b==c);
	}
	
	return bit;
} 



Bit poly(void* ctx){
	int n=100000;
	
	Bit bit(true,PROVER); 

	Number t=1;
	Number x(BITLENGTH,16,PROVER);
	for(int i=0;i<n;i++){
		t=t*(x-i);
	}
	
	Number zero=0;
	bit=t==zero;
	return bit;
} 


void test(NetIO *io,int party,void *ctx,Bit(*f)(void*) ){


	io->counter=0;
	
	auto st=clock();
	if(!judge(io,party,ctx,f)){
		puts("  failed");
		return ;
	} 
	cout<<io->counter/1024.0/1024<<"MB"<<endl;
    
	double ed=clock();
	cout<<(ed-st)/CLOCKS_PER_SEC<<endl;
  
}


int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	io = new NetIO(party==PROVER ? nullptr : "127.0.0.1", port);

	setup_arithmetic_zk(io, party);


	//test(io,party,NULL,inner);
	//test(io,party,NULL,ed);
	//test(io,party,NULL,fac);
	test(io,party,NULL,poly);
    


	delete io;
}
