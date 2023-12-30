package com.shternconsulting.smartbox.sensitive;

public class TerminalService {

	private String _initParameter;

	public TerminalService(String initParameter) {
		this._initParameter = initParameter;
	}
	
	public int DoOperation(String operation, String parameter) {
		String message = String.format("Performing sensitive operation '%s' with parameter '%s', context '%s'", 
										operation, parameter, _initParameter);
		System.out.println(message);
		return message.length();		
	}
	
	public static void main(String[] args) {
        TerminalService service = new TerminalService("Shtern Consulting");
        System.out.println(String.format("Service result: %d", service.DoOperation("talk", "me")));
	}
}
