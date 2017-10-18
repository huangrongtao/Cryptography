package security;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class DES {
static int IP[] = 
{
	       58, 50, 42, 34, 26, 18, 10,  2,
	       60, 52, 44, 36, 28, 20, 12,  4,
	       62, 54, 46, 38, 30, 22, 14,  6,
	       64, 56, 48, 40, 32, 24, 16,  8,
	       57, 49, 41, 33, 25, 17,  9,  1,
	       59, 51, 43, 35, 27, 19, 11,  3,
	       61, 53, 45, 37, 29, 21, 13,  5,
	       63, 55, 47, 39, 31, 23, 15,  7
	};
static int IP_1[]= {
	40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};
static int s_48E[] ={
		 32,  1,  2,  3,  4,  5,
	        4,  5,  6,  7,  8,  9,
	        8,  9, 10, 11, 12, 13,
	       12, 13, 14, 15, 16, 17,
	       16, 17, 18, 19, 20, 21,
	       20, 21, 22, 23, 24, 25,
	       24, 25, 26, 27, 28, 29,
	       28, 29, 30, 31, 32,  1	
};
static int PC_1[]= {
		 57, 49, 41, 33, 25, 17,  9,
	        1, 58, 50, 42, 34, 26, 18,
	       10,  2, 59, 51, 43, 35, 27,
	       19, 11,  3, 60, 52, 44, 36,
	       63, 55, 47, 39, 31, 23, 15,
	        7, 62, 54, 46, 38, 30, 22,
	       14,  6, 61, 53, 45, 37, 29,
	       21, 13,  5, 28, 20, 12,  4
};
static int PC_2[]= {
		 14, 17, 11, 24,  1,  5,
	        3, 28, 15,  6, 21, 10,
	       23, 19, 12,  4, 26,  8,
	       16,  7, 27, 20, 13,  2,
	       41, 52, 31, 37, 47, 55,
	       30, 40, 51, 45, 33, 48,
	       44, 49, 39, 56, 34, 53,
	       46, 42, 50, 36, 29, 32	
};
static int MoveTimes[]= {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static int SBOX[][][]= {
		  //S1 
	    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},   
	    {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},   
	    {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},  
	    {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},  

	    //S2  
	    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},  
	    {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},  
	    {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},  
	    {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},  

	    //S3  
	    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},  
	    {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},  
	    {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},  
	    {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},  

	    //S4  
	    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},  
	    {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
	    {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},  
	    {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},  

	    //S5  
	    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},  
	    {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},  
	    {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},  
	    {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},  

	    //S6  
	    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},  
	    {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},  
	    {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},  
	    {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},  

	    //S7  
	    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},  
	    {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},  
	    {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},  
	    {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},  

	    //S8  
	    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},  
	    {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},  
	    {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},  
	    {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}	
};
static int s_32P[]={
		 16,  7, 20, 21,
	       29, 12, 28, 17,
	        1, 15, 23, 26,
	        5, 18, 31, 10,
	        2,  8, 24, 14,
	       32, 27,  3,  9,
	       19, 13, 30,  6,
	       22, 11,  4, 25
};
public static void main(String []args) {
	int[] key= {
	0,0,1,1,0,1,0,0,
	0,0,1,0,1,1,0,1,
	1,0,1,1,0,1,0,1,
	1,0,1,0,1,0,0,0,
	0,0,0,1,1,1,0,1,
	1,1,0,1,1,0,1,1,
	1,0,0,1,0,0,0,0,
	0,0,0,0,0,1,0,0
	};
	int[] key2= {
			1,0,1,1,0,1,0,0,
			1,0,1,0,1,1,0,1,
			1,0,1,1,0,1,0,1,
			1,0,1,0,1,0,0,0,
			0,0,0,1,1,1,0,1,
			1,1,0,1,1,0,1,1,
			1,0,0,1,0,0,0,0,
			0,0,0,0,0,1,0,0
			};
	String filePath="test.txt";
	String crypePath="test1.txt";
	String decodePath="test2.txt";
	fileEncrypt(filePath,crypePath,key,key2);
	fileDecode(crypePath,decodePath,key,key2);
}
public static void fileEncrypt(String src,String dest,int[] key,int[] key2) {
	char[] bytes=null;
	char[] source=new char[8];
	boolean flag=true;
	int[] plain=new int[64];
	int c=0,count=0;
	int length;
	try {
		InputStream in=new FileInputStream(src);
		OutputStream out=new FileOutputStream(dest,true);
		bytes=new char[in.available()];
		length= bytes.length%8;
		System.out.println(length);
		while((c=in.read())!=-1) {
			bytes[count++]=(char)c;
		}
		in.close();
		//写入最后一行的长度，也就是头部填充1byte，不加密（  加密太麻烦了
		out.write(length);
		//判断是否需要填充
		if(bytes.length%8!=0)
			flag=false;
		//每8个字节加密写入新文件
		for(int i=0;i<bytes.length/8;i++){
				System.arraycopy(bytes, i*8, source, 0, 8);
				byteTobin(source,plain,8);
				int[]result=Encrypt(decode(Encrypt(plain,key),key2),key);
				binTobyte(result,source,8);
				for(char s:source)
					out.write((int)(s));
			}
		//填充0成8byte，再加密写入
		if(!flag) {
			System.arraycopy(bytes, 8*(bytes.length/8), source, 0, bytes.length%8);
			for(int i=(bytes.length%8);i<8;i++)
				source[i]=0;
			byteTobin(source,plain,8);
			int[]result=Encrypt(decode(Encrypt(plain,key),key2),key);
			binTobyte(result,source,8);
			for(char s:source)
				out.write((int)(s));
		}
		out.close();
	} catch (FileNotFoundException e) {
		System.out.println("找不到文件咦");
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
}
public static void fileDecode(String src,String dest,int[] key,int[] key2) {
	char[] bytes=null;
	char[] source=new char[8];
	int[] plain=new int[64];
	int c=0,count=0;
	int length=0;
	try {
		InputStream in=new FileInputStream(src);
		OutputStream out=new FileOutputStream(dest,true);
		//读取原先文件长度,当然是最后一行的长度
		int flag=0;
		length=in.read();
		System.out.println(length);
		bytes=new char[in.available()];
		while((c=in.read())!=-1) {
			bytes[count++]=(char)c;
		}
		in.close();
		if(length!=0)
			flag=1;
		//读取到的字节数肯定是8byte的倍数啦，所以最后一行先放一边，解密其他行数写入文件
		for(int i=0;i<(bytes.length/8)-flag;i++){
				System.arraycopy(bytes, i*8, source, 0, 8);
				byteTobin(source,plain,8);
				int[]result=decode(Encrypt(decode(plain,key),key2),key);
				binTobyte(result,source,8);
				for(char s:source)
					out.write((int)(s));
			}
		//写入截取后的长度
		System.arraycopy(bytes, (bytes.length/8-1)*8, source, 0, 8);
		byteTobin(source,plain,8);
		int[]result=decode(Encrypt(decode(plain,key),key2),key);
		binTobyte(result,source,8);
		for(int i=0;i<length;i++) {
			out.write((int)(source[i]));
		}
		out.close();
	} catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
}
public static void byteTobin( char source[],int bin[],int count) {
	for(int i=0;i<count;i++)
		for(int j=0;j<8;j++)
			if(0x80==((source[i]<<j)&0x80))
				bin[i*8+j]=1;
			else
				bin[i*8+j]=0;
}
public static void binTobyte(int source[],char b[],int bytecount) {
	
	for(int i=0;i<bytecount;i++){
		int start=0;
		for(int j=0;j<8;j++){
			start=start*2+source[i*8+j];
		}
		b[i]=(char)start;
	}
}
public static int[] Encrypt(int[] plaintext,int[] key) {
	int[] LE=new int[32];
	int[] LEtemp=new int[32];
	int[] RE=new int[32];
	int[] Ckey56=new int[28];
	int[] Dkey56=new int[28];
	int[] Cs=new int[28];
	int[] Ds=new int[28];
	int[] key48temp=new int[56];
	int[] plain32=new int[32];
	int[] plain32T=new int[32];
	int[] cryhertext=new int[64];
	int[] cryhertextTemp=new int[64];
	int[] SboxInput=new int[48];
	//将明文混淆并分成上下部分
	for(int i=0;i<64;i++)
		if(i<32)
			LE[i]=plaintext[IP[i]-1];
		else
			RE[i-32]=plaintext[IP[i]-1];
	//将密钥混淆并分成上下部分
	for(int i=0;i<56;i++)
		if(i<28)
			Ckey56[i]=key[PC_1[i]-1];
		else
			Dkey56[i-28]=key[PC_1[i]-1];
	
	//进行16轮的恐怖加密环节
	for(int i=0;i<16;i++) {
		int start=0;
		//按指定的轮数移动相应的位数，得到该轮用到的密钥
		for(int j=MoveTimes[i];j<28;j++,start++){
			Cs[start]=Ckey56[j];
			Ds[start]=Dkey56[j];
		}
		int c=start;
		while(start<28) {
			Cs[start]=Ckey56[28-c-MoveTimes[i]+start-c];
			Ds[start]=Dkey56[28-c-MoveTimes[i]+start-c];
			start++;
		}
		//合并成名副其实的56位密钥
		for(int j=0;j<56;j++)
			if(j<28)
				key48temp[j]=Cs[j];
			else
				key48temp[j]=Ds[j-28];
		//将密钥混淆，RE混淆，相与得到48位Sbox的输入
		for(int j=0;j<48;j++)
			SboxInput[j]=(key48temp[PC_2[j]-1]^RE[s_48E[j]-1]);
		int row;
		int col;
		int result;
		//将输入分成8个6bit的
		for(int j=0;j<8;j++) {
			row=SboxInput[j*6]*2+SboxInput[j*6+5];
			col=SboxInput[j*6+1]*8+SboxInput[j*6+2]*4+SboxInput[j*6+3]*2+SboxInput[j*6+4];
			result=SBOX[j][row][col];//得到当前6bit的输出结果，转成2进制--4bit
			char[] output=Integer.toBinaryString(result).toCharArray();
			int k;
			for(k=0;k<output.length;k++) {
				plain32[j*4+4-output.length+k]=output[k]-'0';
			}
			while(k<4)
				plain32[j*4+3-k++]=0;
		}
		//Sbox获取到32bit的结果，混淆，转置
		for(int j=0;j<32;j++)
			plain32T[j]=plain32[s_32P[j]-1];
		System.arraycopy(LE, 0, LEtemp, 0, LE.length);
		System.arraycopy(RE, 0, LE, 0, RE.length);
		for(int j=0;j<32;j++)	
				plain32[j]=plain32T[28+(j/8)-4*(j%8)];
		//与LE相与得到结果作为下一轮的RE
		for(int j=0;j<32;j++)
			RE[j]=(LEtemp[j]^plain32[j]);
		
	}
	//经过18轮的加密得到的结果合并再混淆，得到密文啦
	for(int i=0;i<64;i++)
		if(i<32)
			cryhertextTemp[i]=RE[i];
		else
			cryhertextTemp[i]=LE[i-32];
	for(int i=0;i<64;i++)
		cryhertext[i]=cryhertextTemp[IP_1[i]-1];
	return cryhertext;
}
public static int[] decode(int[] ciphertext,int[] key) {
	int[] LD=new int[32];
	int[] LDtemp=new int[32];
	int[] RD=new int[32];
	int[] Ckey56=new int[28];
	int[] Dkey56=new int[28];
	int[] Cs=new int[28];
	int[] Ds=new int[28];
	int[] key48temp=new int[56];
	int[] cipher32=new int[32];
	int[] cipher32T=new int[32];
	int[] plaintext=new int[64];
	int[] plaintextTemp=new int[64];
	int[] SboxInput=new int[48];
	for(int i=0;i<64;i++)
		if(i<32)
			LD[i]=ciphertext[IP[i]-1];
		else
			RD[i-32]=ciphertext[IP[i]-1];
	for(int i=0;i<56;i++)
		if(i<28)
			Ckey56[i]=key[PC_1[i]-1];
		else
			Dkey56[i-28]=key[PC_1[i]-1];

	for(int i=0;i<16;i++) {
		int start=0;
		for(int j=MoveTimes[15-i];j<28;j++,start++){
			Cs[start]=Ckey56[j];
			Ds[start]=Dkey56[j];
		}
		int c=start;
		while(start<28) {
			Cs[start]=Ckey56[28-c-MoveTimes[15-i]+start-c];
			Ds[start]=Dkey56[28-c-MoveTimes[15-i]+start-c];
			start++;
		}
		for(int j=0;j<56;j++)
			if(j<28)
				key48temp[j]=Cs[j];
			else
				key48temp[j]=Ds[j-28];
		for(int j=0;j<48;j++)
			SboxInput[j]=(key48temp[PC_2[j]-1]^RD[s_48E[j]-1]);
		int row;
		int col;
		int result;
		for(int j=0;j<8;j++) {
			row=SboxInput[j*6]*2+SboxInput[j*6+5];
			col=SboxInput[j*6+1]*8+SboxInput[j*6+2]*4+SboxInput[j*6+3]*2+SboxInput[j*6+4];
			result=SBOX[j][row][col];
			char[] output=Integer.toBinaryString(result).toCharArray();
			int k;
			for(k=0;k<output.length;k++) {
				cipher32[j*4+4-output.length+k]=output[k]-'0';
			}
			while(k<4)
				cipher32[j*4+3-k++]=0;
		}
		for(int j=0;j<32;j++)
			cipher32T[j]=cipher32[s_32P[j]-1];
		System.arraycopy(LD, 0, LDtemp, 0, LD.length);
		System.arraycopy(RD, 0, LD, 0, RD.length);
		for(int j=0;j<32;j++)	
				cipher32[j]=cipher32T[28+(j/8)-4*(j%8)];
	
		for(int j=0;j<32;j++)
			RD[j]=(LDtemp[j]^cipher32[j]);
	}
	for(int i=0;i<64;i++)
		if(i<32)
			plaintextTemp[i]=RD[i];
		else
			plaintextTemp[i]=LD[i-32];
	for(int i=0;i<64;i++)
		plaintext[i]=plaintextTemp[IP_1[i]-1];
	return plaintext;
}
}
