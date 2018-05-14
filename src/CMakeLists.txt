CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
PROJECT(Analysiser-src)

SET(INCLUDES headers.h roll.h HttpData.h
			 utils.h
	)
SET(CXX_SOURCES HttpData.cpp utils.cpp roll.cpp
			Flow.cpp Session.cpp HttpRespondTime.cpp
	)

ADD_LIBRARY(cxx_src_lib STATIC ${CXX_SOURCES} ${INCLUDES})
