"use client";

import { Moon, Sun } from "lucide-react";
import { useTheme } from "next-themes";
import * as React from "react";
import { Button } from "@/components/ui/button";

export function ThemeToggle({ collapsed = false }: { collapsed?: boolean }) {
  const { theme, setTheme, resolvedTheme } = useTheme();
  const [mounted, setMounted] = React.useState(false);

  React.useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <Button
        variant="ghost"
        size={collapsed ? "icon-sm" : "sm"}
        className="w-full justify-center text-muted-foreground"
        disabled
      >
        <Sun className="h-4 w-4" />
        {!collapsed && <span className="ml-2 text-xs">Theme</span>}
      </Button>
    );
  }

  const isDark = resolvedTheme === "dark";

  return (
    <Button
      variant="ghost"
      size={collapsed ? "icon-sm" : "sm"}
      onClick={() => setTheme(isDark ? "light" : "dark")}
      className={`w-full text-xs font-medium text-muted-foreground hover:text-foreground transition-colors ${
        collapsed ? "justify-center px-0" : "justify-between px-3"
      }`}
      title={isDark ? "Switch to Light Mode" : "Switch to Dark Mode"}
    >
      <div className="flex items-center gap-2">
        {isDark ? (
          <Moon className="h-4 w-4 text-cyan-400" />
        ) : (
          <Sun className="h-4 w-4 text-amber-500" />
        )}
        {!collapsed && <span>{isDark ? "Dark Theme" : "Light Theme"}</span>}
      </div>
      {!collapsed && (
        <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
          {theme}
        </span>
      )}
    </Button>
  );
}
