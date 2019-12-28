
 delete(instrfindall) %% close serial ports
 obj=serial('COM4','BaudRate',115200);%initilize the serial port
%  set(obj,'Terminator','CR');%% set terminator as CR(enter)
%  set(obj,'InputBufferSize',1024) % input buffer size
%  set(obj,'OutputBufferSize',1024) % output buffer size
%  set(obj,'Timeout',0.5) % max time for read&write
%  set(obj,'FlowControl','hardware') % 
 fopen(obj);
 obj.BytesAvailable;
 Filename='YanArduinoData.txt';
 fid=fopen(Filename,'wt');
 for i =1:10000
     y=fscanf(obj,'%s');%read&write action?fread() and fwrite() for binary, use fscanf()and fprintf()for ASCII
     [y1,y2]=size(y);
     fprintf(fid,'\n%s%02X:%02X:%02X:%02X:%02X:%02X |%u | %u | %u| %02d \n',y);
 end

%  while 1
%     y = fscanf(obj,'%s');
%     if strcmp(y,'Counter cleared') % quit if your arduino code send a Serial.println('exit')
%        break
%     end 
%     fprintf(fid,'%02X:%02X:%02X:%02X:%02X:%02X |%u | %u | %u| %02d | %u | %u\n',y);
% end
fclose(fid);
fclose(obj);
delete(obj)
clear obj


 
 
