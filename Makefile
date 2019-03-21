CC  = gcc
CPP = g++

########################################
CFLAGS = -fPIC -lpthread
CPPFLAGS = -fPIC -g -w -std=c++11 -I/opt/dilulib/x86_64/libosip2-5.0.0/include -I/opt/dilulib/x86_64/jrtplib-3.11.1/include \
 -I/opt/dilulib/x86_64/ffmpeg-3.4.5/include/

LINK_FLAGS = -w -g -D__STDC_CONSTANT_MACROS
LIBS =  -lstdc++ -lpthread -L/opt/dilulib/x86_64/libosip2-5.0.0/lib -losip2 /opt/dilulib/x86_64/libosip2-5.0.0/lib/libosipparser2.a \
 -leXosip2 /opt/dilulib/x86_64/jrtplib-3.11.1/lib/libjrtp.a -L/opt/dilulib/x86_64/ffmpeg-3.4.5/lib -lavcodec -lavformat -lavutil -lswscale \
 -lopencv_core -lopencv_imgproc -lopencv_highgui -lopencv_video 

#########################################################

PROGRAM = gb28181

OBJS = 

# The directories in which source files reside.  
# At least one path should be specified.  
# SRCDIRS   := .        # current directory  
SRCDIRS   :=  . 
# The source file types (headers excluded).  
# At least one type should be specified.  
# The valid suffixes are among of .c, .C, .cc, .cpp, .CPP, .c++, .cp, or .cxx.  
# SRCEXTS   := .c      # C program  
# SRCEXTS   := .cpp    # C++ program  
# SRCEXTS   := .c .cpp # C/C++ program  
SRCEXTS   := .cc .cpp

ifneq ($(SRCDIRS),)
ifneq ($(SRCEXTS),)
	SOURCES = $(foreach d,$(SRCDIRS),$(wildcard $(addprefix $(d)/*,$(SRCEXTS))))  
	OBJS += $(foreach x,$(SRCEXTS), $(patsubst %$(x),%.o,$(filter %$(x),$(SOURCES))))  
endif
endif

DEBUGOBJS = $(patsubst %.o,%.d,$(OBJS))  

$(PROGRAM): $(OBJS)
	$(CPP) $(LINK_FLAGS) -o $@  $(OBJS) $(LIBS) 

clean:
	clear
	rm -rf $(OBJS) *.o $(PROGRAM)

install:
	cp -f $(PROGRAM) /e/nonsys/tools/video/
#$(OBJS):%.o :%.c  先用$(OBJS)中的一项，比如foo.o: %.o : %.c  含义为:试着用%.o匹配foo.o。如果成功%就等于foo。如果不成功，  
# Make就会警告，然后。给foo.o添加依赖文件foo.c(用foo替换了%.c里的%)  
# 也可以不要下面的这个生成规则，因为下面的 include $(DEF)  就隐含了。此处为了明了，易懂。故留着  
#compile c source file
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
%.o: %.C
	$(CC) $(CFLAGS) -c $< -o $@

#compile c++ source file
%.o: %.cpp
	$(CPP) $(CPPFLAGS) -c $< -o $@
%.o: %.cp
	$(CPP) $(CPPFLAGS) -c $< -o $@
%.o: %.CPP
	$(CPP) $(CPPFLAGS) -c $< -o $@
%.o: %.cc
	$(CPP) $(CPPFLAGS) -c $< -o $@
%.o: %.cxx
	$(CPP) $(CPPFLAGS) -c $< -o $@
%.o: %.c++
	$(CPP) $(CPPFLAGS) -c $< -o $@
