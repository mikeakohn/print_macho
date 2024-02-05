
default:
	@+make -C build

clean:
	@rm -f print_macho build/*.o
	@echo "Clean!"

