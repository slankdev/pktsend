
/*
 * MIT License
 *
 * Copyright (c) 2017 Susanoo G
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
/**
 * @file   slankdev/asciicode.h
 * @brief  asciicode
 * @author Hiroki SHIROKURA
 * @date   2017.4.2
 */



#pragma once



namespace slankdev {


enum keycode {
  AC_NUL            =  0x00,  /* NUL  */
  AC_Ctrl_A         =  0x01,  /* SOH  */
  AC_Ctrl_B         =  0x02,  /* STX  */
  AC_Ctrl_C         =  0x03,  /* ETX  */
  AC_Ctrl_D         =  0x04,  /* EOT  */
  AC_Ctrl_E         =  0x05,  /* ENQ  */
  AC_Ctrl_F         =  0x06,  /* ACK  */
  AC_Ctrl_G         =  0x07,  /* BEL  */
  AC_Backspace      =  0x08,  /* BS   */
  AC_Tab            =  0x09,  /* HT   */
  AC_Ctrl_J         =  0x0A,  /* LF   */
  AC_Ctrl_K         =  0x0B,  /* VT   */
  AC_Ctrl_L         =  0x0C,  /* FF   */
  AC_Ctrl_M         =  0x0D,  /* CR   */
  AC_Ctrl_N         =  0x0E,  /* SO   */
  AC_Ctrl_O         =  0x0F,  /* SI   */
  AC_Ctrl_P         =  0x10,  /* DLE  */
  AC_Ctrl_Q         =  0x11,  /* DC1  */
  AC_Ctrl_R         =  0x12,  /* DC2  */
  AC_Ctrl_S         =  0x13,  /* DC3  */
  AC_Ctrl_T         =  0x14,  /* DC4  */
  AC_Ctrl_U         =  0x15,  /* NAK  */
  AC_Ctrl_V         =  0x16,  /* SYN  */
  AC_Ctrl_W         =  0x17,  /* ETB  */
  AC_Ctrl_X         =  0x18,  /* CAN  */
  AC_Ctrl_Y         =  0x19,  /* EM   */
  AC_Ctrl_Z         =  0x1A,  /* SUB  */
  AC_ESC            =  0x1B,  /* ESC  */
  AC_Ctrl_Bslash    =  0x1C,  /* FS   */
  AC_NOUSE0         =  0x1D,  /* GS   */
  AC_Ctrl_Hat       =  0x1E,  /* RS   */
  AC_Ctrl_Underbar  =  0x1F,  /* US   */
  AC_Space          =  0x20,  /*      */
  AC_Exclament      =  0x21,  /* !    */
  AC_Doublequot     =  0x22,  /* "    */
  AC_Sharp          =  0x23,  /* #    */
  AC_Daller         =  0x24,  /* $    */
  AC_Percent        =  0x25,  /* %    */
  AC_And            =  0x26,  /* &    */
  AC_Singlequot     =  0x27,  /* '    */
  AC_Rparent        =  0x28,  /* (    */
  AC_Crparent       =  0x29,  /* )    */
  AC_Aster          =  0x2A,  /* *    */
  AC_Plus           =  0x2B,  /* +    */
  AC_Comma          =  0x2C,  /* ,    */
  AC_Hyphen         =  0x2D,  /* -    */
  AC_Dot            =  0x2E,  /* .    */
  AC_Slash          =  0x2F,  /* /    */
  AC_0              =  0x30,  /* 0    */
  AC_1              =  0x31,  /* 1    */
  AC_2              =  0x32,  /* 2    */
  AC_3              =  0x33,  /* 3    */
  AC_4              =  0x34,  /* 4    */
  AC_5              =  0x35,  /* 5    */
  AC_6              =  0x36,  /* 6    */
  AC_7              =  0x37,  /* 7    */
  AC_8              =  0x38,  /* 8    */
  AC_9              =  0x39,  /* 9    */
  AC_Coron          =  0x3A,  /* :    */
  AC_Semicoron      =  0x3B,  /* ;    */
  AC_Abracket       =  0x3C,  /* <    */
  AC_Equal          =  0x3D,  /* =    */
  AC_Cabracket      =  0x3E,  /* >    */
  AC_Question       =  0x3F,  /* ?    */
  AC_Atmark         =  0x40,  /* @    */
  AC_A              =  0x41,  /* A    */
  AC_B              =  0x42,  /* B    */
  AC_C              =  0x43,  /* C    */
  AC_D              =  0x44,  /* D    */
  AC_E              =  0x45,  /* E    */
  AC_F              =  0x46,  /* F    */
  AC_G              =  0x47,  /* G    */
  AC_H              =  0x48,  /* H    */
  AC_I              =  0x49,  /* I    */
  AC_J              =  0x4A,  /* J    */
  AC_K              =  0x4B,  /* K    */
  AC_L              =  0x4C,  /* L    */
  AC_M              =  0x4D,  /* M    */
  AC_N              =  0x4E,  /* N    */
  AC_O              =  0x4F,  /* O    */
  AC_P              =  0x50,  /* P    */
  AC_Q              =  0x51,  /* Q    */
  AC_R              =  0x52,  /* R    */
  AC_S              =  0x53,  /* S    */
  AC_T              =  0x54,  /* T    */
  AC_U              =  0x55,  /* U    */
  AC_V              =  0x56,  /* V    */
  AC_W              =  0x57,  /* W    */
  AC_X              =  0x58,  /* X    */
  AC_Y              =  0x59,  /* Y    */
  AC_Z              =  0x5A,  /* Z    */
  AC_Sbrackets      =  0x5B,  /* [    */
  AC_Backslash      =  0x5C,  /* \    */
  AC_CSbrackets     =  0x5D,  /* ]    */
  AC_Hat            =  0x5E,  /* ^    */
  AC_Underbar       =  0x5F,  /* _    */
  AC_Apos           =  0x60,  /* `    */
  AC_a              =  0x61,  /* a    */
  AC_b              =  0x62,  /* b    */
  AC_c              =  0x63,  /* c    */
  AC_d              =  0x64,  /* d    */
  AC_e              =  0x65,  /* e    */
  AC_f              =  0x66,  /* f    */
  AC_g              =  0x67,  /* g    */
  AC_h              =  0x68,  /* h    */
  AC_i              =  0x69,  /* i    */
  AC_j              =  0x6A,  /* j    */
  AC_k              =  0x6B,  /* k    */
  AC_l              =  0x6C,  /* l    */
  AC_m              =  0x6D,  /* m    */
  AC_n              =  0x6E,  /* n    */
  AC_o              =  0x6F,  /* o    */
  AC_p              =  0x70,  /* p    */
  AC_q              =  0x71,  /* q    */
  AC_r              =  0x72,  /* r    */
  AC_s              =  0x73,  /* s    */
  AC_t              =  0x74,  /* t    */
  AC_u              =  0x75,  /* u    */
  AC_v              =  0x76,  /* v    */
  AC_w              =  0x77,  /* w    */
  AC_x              =  0x78,  /* x    */
  AC_y              =  0x79,  /* y    */
  AC_z              =  0x7A,  /* z    */
  AC_Cbracket       =  0x7B,  /* {    */
  AC_Vline          =  0x7C,  /* |    */
  AC_CCbracket      =  0x7D,  /* }    */
  AC_Childa         =  0x7E,  /* ~    */
  AC_Delete         =  0x7F,  /* DEL  */
};

} /* namespace slankdev */
