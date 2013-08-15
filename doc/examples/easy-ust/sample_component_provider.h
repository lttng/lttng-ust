/*
 * Copyright (C) 2011-2012  Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright (C) 2011-2012  Matthew Khouzam <matthew.khouzam@ericsson.com> 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
/*
 * Sample lttng-ust tracepoint provider. 
 */

/*
 * First part: defines
 * We undef a macro before defining it as it can be used in several files.
 */

/*  
 * Must be included before include tracepoint provider 
 * ex.: project_event
 * ex.: project_component_event
 *
 * Optional company name goes here
 * ex.: com_efficios_project_component_event
 *
 * In this example, "sample" is the project, and "component" is the
 * component.
 */
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER sample_component

/*
 * include file (this files's name)
 */
#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./sample_component_provider.h"

/*
 * Add this precompiler conditionals to ensure the tracepoint event generation
 * can include this file more than once.
 */
#if !defined(_SAMPLE_COMPONENT_PROVIDER_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _SAMPLE_COMPONENT_PROVIDER_H
/*
 * Add this to allow programs to call "tracepoint(...):
 */ 
#include <lttng/tracepoint.h> 

/*
 * The following tracepoint event writes a message (c string) into the
 * field message of the trace event message in the provider
 * sample_component in other words:
 *
 *    sample_component:message:message = text. 
 */
TRACEPOINT_EVENT(
	/*
	 * provider name, not a variable but a string starting with a letter
	 * and containing either letters, numbers or underscores. 
	 * Needs to be the same as TRACEPOINT_PROVIDER
	 */
	sample_component,
	/*
	 * tracepoint name, same format as sample provider. Does not need to be 
	 * declared before. in this case the name is "message" 
	 */
	message,
	/*
	 * TP_ARGS macro contains the arguments passed for the tracepoint 
	 * it is in the following format
	 * 		TP_ARGS( type1, name1, type2, name2, ... type10, name10)
	 * where there can be from zero to ten elements. 
	 * typeN is the datatype, such as int, struct or double **. 
	 * name is the variable name (in "int myInt" the name would be myint) 
	 * 		TP_ARGS() is valid to mean no arguments
	 * 		TP_ARGS( void ) is valid too
	 */ 
	TP_ARGS(char *, text),
	/*
	 * TP_FIELDS describes how to write the fields of the trace event. 
	 * You can use the args here
	 */
	TP_FIELDS(
	/*
	 * The ctf_string macro takes a c string and writes it into a field
	 * named "message" 
	 */ 
		ctf_string(message, text)
	)
)
/*
 * Trace loglevel, shows the level of the trace event. It can be TRACE_EMERG, 
 * TRACE_ALERT, TRACE_CRIT, TRACE_ERR, TRACE_WARNING, TRACE_INFO or others. 
 * If this is not set, TRACE_DEFAULT is assumed.
 * The first two arguments identify the tracepoint
 * See details in <lttng/tracepoint.h> line 347
 */
TRACEPOINT_LOGLEVEL(
       /*
        * The provider name, must be the same as the provider name in the 
        * TRACEPOINT_EVENT and as TRACEPOINT_PROVIDER above.
        */
	sample_component, 
       /* 
        * The tracepoint name, must be the same as the tracepoint name in the 
        * TRACEPOINT_EVENT
        */
	message, 
       /*
        * The tracepoint loglevel. Warning, some levels are abbreviated and
        * others are not, please see <lttng/tracepoint.h>
        */
	TRACE_WARNING)

#endif /* _SAMPLE_COMPONENT_PROVIDER_H */

/*
 * Add this after defining the tracepoint events to expand the macros. 
 */ 
#include <lttng/tracepoint-event.h>
