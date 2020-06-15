 #include <emp-tool/emp-tool.h>
#include "ESwap/ESwap.h"
using namespace emp;
using namespace std;


int port, party;
NetIO * io;
CircuitFile sha("/home/kzoacn/emp-all/ESwap/files/sha-256.txt");
string sha0="0101111111101100111010110110011011111111110010000110111100111000110110010101001001111000011011000110110101101001011011000111100111000010110110111100001000111001110111010100111010010001101101000110011100101001110101110011101000100111111110110101011111101001";


string padding(string chars){
    string ans;

    long long l=chars.length()*8;
    for(int i=0;i<chars.length();i++){
        unsigned char c=chars[i];
        for(int j=0;j<8;j++){
            ans+=(char)(c>>(7-j)&1);
        }
    }
    
    
    ans+=(char)1;
    while(ans.length()%512!=448){
        ans+=(char)0;
    }
    for(int i=0;i<8;i++){
        unsigned char c=*(((unsigned char*)&l)+7-i);
        for(int j=0;j<8;j++)
            ans+=(c>>(7-j)&1) ? (char)1 : (char)0;
    }
    return ans;
}


char to_hex(int x){
    if(x<10)
        return '0'+x;
    return 'A'+x-10;
}

string to_hex(string s){
    string ans;
    for(int i=0;i<(int)s.length();i+=4){
        int x=0;
        for(int j=0;j<4;j++)
            x=x<<1 | (s[i+j]-'0');
        ans+=to_hex(x);
    }
    return ans;
}




Bit proofsha(void* ctx){
	Bit ans(true,PUBLIC);
    //CircuitFile sha256;

    for(int T=0;T<128;T++){
        Bit out[256],in1[512],in2[512];
        

        string input=padding("0");
        for(int i=0;i<512;i++){
            in1[i]=Bit(input[i],ALICE);       
        }
        CircuitFile sha256=sha;
        sha256.compute((block*)out,(block*)in1,(block*)in2);


        for(int i=0;i<256;i++){
            Bit res(out[i]);
            Bit cor(sha0[i]-'0',PUBLIC);
            ans=ans&(res==cor); 
        }
    }
	return ans;
}

int main(int argc, char** argv) {
	parse_party_and_port(argv, &party, &port);
	io = new NetIO(party==PROVER ? nullptr : "127.0.0.1", port);
    
	setup_arithmetic_zk(io, party);


	if(!judge(io,party,NULL,proofsha)){
		error("proofsha failed");
		return 0;
	}
    
   
    



    puts("Yes");

	delete io;
}
