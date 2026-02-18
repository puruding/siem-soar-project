import { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Switch } from '@/components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import {
  Settings,
  User,
  Bell,
  Shield,
  Palette,
  Globe,
  Database,
  Key,
  Mail,
  Building2,
  Clock,
  Save,
  RefreshCw,
  Moon,
  Sun,
  Monitor,
  Variable,
  Plus,
  Edit2,
  Trash2,
  Search,
  Code2,
  Hash,
  ToggleLeft,
  List,
  Braces,
} from 'lucide-react';
import { Textarea } from '@/components/ui/textarea';
import { useThemeStore } from '@/stores/themeStore';
import { useToast } from '@/components/ui/toaster';
import { cn } from '@/lib/utils';
import { useOrganizationVariables } from '@/features/playbooks/stores/organizationVariablesStore';
import type { PlaybookVariable, VariableType } from '@/features/playbooks/components/VariablePanel';

export function SettingsPage() {
  const { theme, setTheme } = useThemeStore();
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState('general');

  // Organization Variables
  const { variables: orgVariables, addVariable, updateVariable, deleteVariable } = useOrganizationVariables();
  const [varSearchQuery, setVarSearchQuery] = useState('');
  const [editingVar, setEditingVar] = useState<PlaybookVariable | null>(null);
  const [isAddingVar, setIsAddingVar] = useState(false);
  const [newVar, setNewVar] = useState<Omit<PlaybookVariable, 'id' | 'scope'>>({
    name: '',
    type: 'string',
    value: '',
    description: '',
  });
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);

  const filteredOrgVariables = orgVariables.filter(
    (v) =>
      v.name.toLowerCase().includes(varSearchQuery.toLowerCase()) ||
      v.description?.toLowerCase().includes(varSearchQuery.toLowerCase())
  );

  const getTypeIcon = (type: VariableType) => {
    switch (type) {
      case 'string':
        return <Code2 className="w-3 h-3" />;
      case 'number':
        return <Hash className="w-3 h-3" />;
      case 'boolean':
        return <ToggleLeft className="w-3 h-3" />;
      case 'array':
        return <List className="w-3 h-3" />;
      case 'object':
        return <Braces className="w-3 h-3" />;
    }
  };

  const formatValue = (value: unknown, type: VariableType): string => {
    if (value === null || value === undefined) return 'null';
    switch (type) {
      case 'string':
        return `"${value}"`;
      case 'number':
      case 'boolean':
        return String(value);
      case 'array':
      case 'object':
        return JSON.stringify(value, null, 2);
      default:
        return String(value);
    }
  };

  const handleAddVariable = () => {
    if (!newVar.name.trim()) return;

    let parsedValue = newVar.value;
    try {
      switch (newVar.type) {
        case 'number':
          parsedValue = Number(newVar.value);
          break;
        case 'boolean':
          parsedValue = newVar.value === 'true';
          break;
        case 'array':
        case 'object':
          parsedValue = JSON.parse(newVar.value as string);
          break;
      }
    } catch {
      // Keep as string if parsing fails
    }

    addVariable({ ...newVar, value: parsedValue, scope: 'organization' });
    setNewVar({ name: '', type: 'string', value: '', description: '' });
    setIsAddingVar(false);
    toast({
      title: 'Variable Added',
      description: `Organization variable "${newVar.name}" has been created.`,
    });
  };

  const handleUpdateVariable = () => {
    if (!editingVar) return;

    let parsedValue = editingVar.value;
    try {
      switch (editingVar.type) {
        case 'number':
          parsedValue = Number(editingVar.value);
          break;
        case 'boolean':
          parsedValue = editingVar.value === 'true' || editingVar.value === true;
          break;
        case 'array':
        case 'object':
          if (typeof editingVar.value === 'string') {
            parsedValue = JSON.parse(editingVar.value);
          }
          break;
      }
    } catch {
      // Keep as-is if parsing fails
    }

    updateVariable(editingVar.id, { ...editingVar, value: parsedValue });
    setEditingVar(null);
    toast({
      title: 'Variable Updated',
      description: `Organization variable "${editingVar.name}" has been updated.`,
    });
  };

  const handleDeleteVariable = (id: string, name: string) => {
    deleteVariable(id);
    setDeleteConfirmId(null);
    toast({
      title: 'Variable Deleted',
      description: `Organization variable "${name}" has been deleted.`,
    });
  };

  // General settings state
  const [generalSettings, setGeneralSettings] = useState({
    organizationName: 'ACME Corporation',
    timezone: 'Asia/Seoul',
    dateFormat: 'YYYY-MM-DD',
    language: 'ko',
  });

  // Notification settings state
  const [notificationSettings, setNotificationSettings] = useState({
    emailAlerts: true,
    slackAlerts: true,
    criticalOnly: false,
    digestFrequency: 'realtime',
    emailAddress: 'soc@company.com',
    slackWebhook: 'https://hooks.slack.com/services/xxx',
  });

  // Security settings state
  const [securitySettings, setSecuritySettings] = useState({
    mfaEnabled: true,
    sessionTimeout: 30,
    ipWhitelist: '',
    auditLogging: true,
    passwordPolicy: 'strong',
  });

  const handleSaveGeneral = () => {
    toast({
      title: 'Settings Saved',
      description: 'General settings have been updated successfully.',
    });
  };

  const handleSaveNotifications = () => {
    toast({
      title: 'Settings Saved',
      description: 'Notification settings have been updated successfully.',
    });
  };

  const handleSaveSecurity = () => {
    toast({
      title: 'Settings Saved',
      description: 'Security settings have been updated successfully.',
    });
  };

  const tabItems = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'variables', label: 'Organization Variables', icon: Variable },
    { id: 'appearance', label: 'Appearance', icon: Palette },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'integrations', label: 'Integrations', icon: Database },
    { id: 'api', label: 'API Keys', icon: Key },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
        <p className="text-muted-foreground">
          Manage your organization settings and preferences
        </p>
      </div>

      <div className="flex gap-6">
        {/* Sidebar Navigation */}
        <Card className="w-64 shrink-0 h-fit">
          <CardContent className="p-2">
            <nav className="space-y-1">
              {tabItems.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.id}
                    onClick={() => setActiveTab(item.id)}
                    className={cn(
                      'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                      activeTab === item.id
                        ? 'bg-primary text-primary-foreground'
                        : 'hover:bg-muted text-muted-foreground hover:text-foreground'
                    )}
                  >
                    <Icon className="w-4 h-4" />
                    {item.label}
                  </button>
                );
              })}
            </nav>
          </CardContent>
        </Card>

        {/* Content Area */}
        <div className="flex-1 min-w-0">
          <ScrollArea className="h-[calc(100vh-220px)]">
            {/* General Settings */}
            {activeTab === 'general' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Building2 className="w-5 h-5" />
                    General Settings
                  </CardTitle>
                  <CardDescription>
                    Configure your organization's basic settings
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-2">
                    <Label htmlFor="orgName">Organization Name</Label>
                    <Input
                      id="orgName"
                      value={generalSettings.organizationName}
                      onChange={(e) =>
                        setGeneralSettings({ ...generalSettings, organizationName: e.target.value })
                      }
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="timezone">Timezone</Label>
                      <Select
                        value={generalSettings.timezone}
                        onValueChange={(value) =>
                          setGeneralSettings({ ...generalSettings, timezone: value })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="Asia/Seoul">Asia/Seoul (KST)</SelectItem>
                          <SelectItem value="UTC">UTC</SelectItem>
                          <SelectItem value="America/New_York">America/New_York (EST)</SelectItem>
                          <SelectItem value="Europe/London">Europe/London (GMT)</SelectItem>
                          <SelectItem value="Asia/Tokyo">Asia/Tokyo (JST)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="dateFormat">Date Format</Label>
                      <Select
                        value={generalSettings.dateFormat}
                        onValueChange={(value) =>
                          setGeneralSettings({ ...generalSettings, dateFormat: value })
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="YYYY-MM-DD">YYYY-MM-DD</SelectItem>
                          <SelectItem value="DD/MM/YYYY">DD/MM/YYYY</SelectItem>
                          <SelectItem value="MM/DD/YYYY">MM/DD/YYYY</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="language">Language</Label>
                    <Select
                      value={generalSettings.language}
                      onValueChange={(value) =>
                        setGeneralSettings({ ...generalSettings, language: value })
                      }
                    >
                      <SelectTrigger className="w-[200px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ko">한국어</SelectItem>
                        <SelectItem value="en">English</SelectItem>
                        <SelectItem value="ja">日本語</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <Separator />

                  <div className="flex justify-end">
                    <Button onClick={handleSaveGeneral}>
                      <Save className="w-4 h-4 mr-2" />
                      Save Changes
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Organization Variables */}
            {activeTab === 'variables' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Variable className="w-5 h-5 text-teal-500" />
                    Organization Variables
                  </CardTitle>
                  <CardDescription>
                    Define variables that are shared across all playbooks in your organization
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {/* Search and Add */}
                  <div className="flex items-center gap-3">
                    <div className="relative flex-1">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                      <Input
                        placeholder="Search variables..."
                        value={varSearchQuery}
                        onChange={(e) => setVarSearchQuery(e.target.value)}
                        className="pl-9"
                      />
                    </div>
                    <Button onClick={() => setIsAddingVar(true)}>
                      <Plus className="w-4 h-4 mr-2" />
                      Add Variable
                    </Button>
                  </div>

                  {/* Add Variable Form */}
                  {isAddingVar && (
                    <Card className="border-teal-500/30 bg-teal-500/5">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base">New Organization Variable</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label>Name</Label>
                            <Input
                              placeholder="variable_name"
                              value={newVar.name}
                              onChange={(e) => setNewVar({ ...newVar, name: e.target.value })}
                            />
                          </div>
                          <div className="space-y-2">
                            <Label>Type</Label>
                            <Select
                              value={newVar.type}
                              onValueChange={(value: VariableType) => setNewVar({ ...newVar, type: value })}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="string">String</SelectItem>
                                <SelectItem value="number">Number</SelectItem>
                                <SelectItem value="boolean">Boolean</SelectItem>
                                <SelectItem value="array">Array</SelectItem>
                                <SelectItem value="object">Object</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label>Value</Label>
                          {newVar.type === 'boolean' ? (
                            <Select
                              value={String(newVar.value)}
                              onValueChange={(value) => setNewVar({ ...newVar, value })}
                            >
                              <SelectTrigger>
                                <SelectValue placeholder="Select value" />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="true">true</SelectItem>
                                <SelectItem value="false">false</SelectItem>
                              </SelectContent>
                            </Select>
                          ) : newVar.type === 'array' || newVar.type === 'object' ? (
                            <Textarea
                              placeholder={newVar.type === 'array' ? '["item1", "item2"]' : '{"key": "value"}'}
                              value={String(newVar.value)}
                              onChange={(e) => setNewVar({ ...newVar, value: e.target.value })}
                              className="font-mono text-sm"
                              rows={4}
                            />
                          ) : (
                            <Input
                              type={newVar.type === 'number' ? 'number' : 'text'}
                              placeholder="Enter value..."
                              value={String(newVar.value)}
                              onChange={(e) => setNewVar({ ...newVar, value: e.target.value })}
                            />
                          )}
                        </div>
                        <div className="space-y-2">
                          <Label>Description</Label>
                          <Input
                            placeholder="Variable description..."
                            value={newVar.description}
                            onChange={(e) => setNewVar({ ...newVar, description: e.target.value })}
                          />
                        </div>
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" onClick={() => setIsAddingVar(false)}>
                            Cancel
                          </Button>
                          <Button onClick={handleAddVariable} disabled={!newVar.name.trim()}>
                            Add Variable
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  {/* Edit Variable Form */}
                  {editingVar && (
                    <Card className="border-blue-500/30 bg-blue-500/5">
                      <CardHeader className="pb-3">
                        <CardTitle className="text-base">Edit Variable: {editingVar.name}</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                          <div className="space-y-2">
                            <Label>Name</Label>
                            <Input
                              value={editingVar.name}
                              onChange={(e) => setEditingVar({ ...editingVar, name: e.target.value })}
                            />
                          </div>
                          <div className="space-y-2">
                            <Label>Type</Label>
                            <Select
                              value={editingVar.type}
                              onValueChange={(value: VariableType) => setEditingVar({ ...editingVar, type: value })}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="string">String</SelectItem>
                                <SelectItem value="number">Number</SelectItem>
                                <SelectItem value="boolean">Boolean</SelectItem>
                                <SelectItem value="array">Array</SelectItem>
                                <SelectItem value="object">Object</SelectItem>
                              </SelectContent>
                            </Select>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Label>Value</Label>
                          {editingVar.type === 'boolean' ? (
                            <Select
                              value={String(editingVar.value)}
                              onValueChange={(value) => setEditingVar({ ...editingVar, value })}
                            >
                              <SelectTrigger>
                                <SelectValue />
                              </SelectTrigger>
                              <SelectContent>
                                <SelectItem value="true">true</SelectItem>
                                <SelectItem value="false">false</SelectItem>
                              </SelectContent>
                            </Select>
                          ) : editingVar.type === 'array' || editingVar.type === 'object' ? (
                            <Textarea
                              value={
                                typeof editingVar.value === 'string'
                                  ? editingVar.value
                                  : JSON.stringify(editingVar.value, null, 2)
                              }
                              onChange={(e) => setEditingVar({ ...editingVar, value: e.target.value })}
                              className="font-mono text-sm"
                              rows={6}
                            />
                          ) : (
                            <Input
                              type={editingVar.type === 'number' ? 'number' : 'text'}
                              value={String(editingVar.value)}
                              onChange={(e) => setEditingVar({ ...editingVar, value: e.target.value })}
                            />
                          )}
                        </div>
                        <div className="space-y-2">
                          <Label>Description</Label>
                          <Input
                            value={editingVar.description || ''}
                            onChange={(e) => setEditingVar({ ...editingVar, description: e.target.value })}
                          />
                        </div>
                        <div className="flex justify-end gap-2">
                          <Button variant="outline" onClick={() => setEditingVar(null)}>
                            Cancel
                          </Button>
                          <Button onClick={handleUpdateVariable}>
                            Save Changes
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  )}

                  {/* Variables List */}
                  <div className="space-y-3">
                    {filteredOrgVariables.length === 0 ? (
                      <div className="py-12 text-center text-muted-foreground">
                        {varSearchQuery
                          ? `No variables match "${varSearchQuery}"`
                          : 'No organization variables defined yet'}
                      </div>
                    ) : (
                      filteredOrgVariables.map((variable) => (
                        <div
                          key={variable.id}
                          className="p-4 rounded-lg border hover:border-teal-500/30 transition-colors"
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-2">
                                <span className="font-mono font-medium">{variable.name}</span>
                                <Badge
                                  variant="outline"
                                  className="text-xs text-teal-500 border-teal-500/30 bg-teal-500/10"
                                >
                                  <Building2 className="w-3 h-3 mr-1" />
                                  Organization
                                </Badge>
                                <Badge variant="secondary" className="text-xs">
                                  {getTypeIcon(variable.type)}
                                  <span className="ml-1 capitalize">{variable.type}</span>
                                </Badge>
                              </div>
                              {variable.description && (
                                <p className="text-sm text-muted-foreground mb-2">
                                  {variable.description}
                                </p>
                              )}
                              <div className="p-2 rounded bg-muted/50 font-mono text-sm">
                                <pre className="whitespace-pre-wrap break-all max-h-20 overflow-y-auto">
                                  {formatValue(variable.value, variable.type)}
                                </pre>
                              </div>
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              {deleteConfirmId === variable.id ? (
                                <>
                                  <Button
                                    variant="destructive"
                                    size="sm"
                                    onClick={() => handleDeleteVariable(variable.id, variable.name)}
                                  >
                                    Confirm
                                  </Button>
                                  <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => setDeleteConfirmId(null)}
                                  >
                                    Cancel
                                  </Button>
                                </>
                              ) : (
                                <>
                                  <Button
                                    variant="outline"
                                    size="icon"
                                    className="w-8 h-8"
                                    onClick={() => setEditingVar(variable)}
                                    disabled={!!editingVar}
                                  >
                                    <Edit2 className="w-4 h-4" />
                                  </Button>
                                  <Button
                                    variant="outline"
                                    size="icon"
                                    className="w-8 h-8 text-red-500 hover:text-red-500"
                                    onClick={() => setDeleteConfirmId(variable.id)}
                                  >
                                    <Trash2 className="w-4 h-4" />
                                  </Button>
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Info Box */}
                  <div className="p-4 rounded-lg bg-teal-500/5 border border-teal-500/20">
                    <p className="text-sm text-muted-foreground">
                      <strong className="text-teal-500">Note:</strong> Organization variables are available
                      in all playbooks as read-only. Use the syntax{' '}
                      <code className="px-1 py-0.5 rounded bg-muted font-mono text-xs">
                        {'{{variable_name}}'}
                      </code>{' '}
                      to reference them in your playbook configurations.
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Appearance Settings */}
            {activeTab === 'appearance' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Palette className="w-5 h-5" />
                    Appearance
                  </CardTitle>
                  <CardDescription>
                    Customize the look and feel of the dashboard
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <Label>Theme</Label>
                    <div className="grid grid-cols-3 gap-4">
                      <button
                        onClick={() => setTheme('light')}
                        className={cn(
                          'flex flex-col items-center gap-2 p-4 rounded-lg border-2 transition-colors',
                          theme === 'light'
                            ? 'border-primary bg-primary/5'
                            : 'border-border hover:border-primary/50'
                        )}
                      >
                        <Sun className="w-8 h-8" />
                        <span className="text-sm font-medium">Light</span>
                      </button>
                      <button
                        onClick={() => setTheme('dark')}
                        className={cn(
                          'flex flex-col items-center gap-2 p-4 rounded-lg border-2 transition-colors',
                          theme === 'dark'
                            ? 'border-primary bg-primary/5'
                            : 'border-border hover:border-primary/50'
                        )}
                      >
                        <Moon className="w-8 h-8" />
                        <span className="text-sm font-medium">Dark</span>
                      </button>
                      <button
                        onClick={() => setTheme('system')}
                        className={cn(
                          'flex flex-col items-center gap-2 p-4 rounded-lg border-2 transition-colors',
                          theme === 'system'
                            ? 'border-primary bg-primary/5'
                            : 'border-border hover:border-primary/50'
                        )}
                      >
                        <Monitor className="w-8 h-8" />
                        <span className="text-sm font-medium">System</span>
                      </button>
                    </div>
                  </div>

                  <Separator />

                  <div className="space-y-4">
                    <Label>Dashboard Density</Label>
                    <Select defaultValue="comfortable">
                      <SelectTrigger className="w-[200px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="compact">Compact</SelectItem>
                        <SelectItem value="comfortable">Comfortable</SelectItem>
                        <SelectItem value="spacious">Spacious</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Notification Settings */}
            {activeTab === 'notifications' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bell className="w-5 h-5" />
                    Notification Settings
                  </CardTitle>
                  <CardDescription>
                    Configure how you receive alerts and notifications
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label>Email Alerts</Label>
                        <p className="text-sm text-muted-foreground">
                          Receive alerts via email
                        </p>
                      </div>
                      <Switch
                        checked={notificationSettings.emailAlerts}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, emailAlerts: checked })
                        }
                      />
                    </div>

                    {notificationSettings.emailAlerts && (
                      <div className="ml-4 space-y-2">
                        <Label htmlFor="email">Email Address</Label>
                        <Input
                          id="email"
                          type="email"
                          value={notificationSettings.emailAddress}
                          onChange={(e) =>
                            setNotificationSettings({
                              ...notificationSettings,
                              emailAddress: e.target.value,
                            })
                          }
                        />
                      </div>
                    )}

                    <Separator />

                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label>Slack Alerts</Label>
                        <p className="text-sm text-muted-foreground">
                          Send alerts to Slack channel
                        </p>
                      </div>
                      <Switch
                        checked={notificationSettings.slackAlerts}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, slackAlerts: checked })
                        }
                      />
                    </div>

                    {notificationSettings.slackAlerts && (
                      <div className="ml-4 space-y-2">
                        <Label htmlFor="slack">Slack Webhook URL</Label>
                        <Input
                          id="slack"
                          type="url"
                          value={notificationSettings.slackWebhook}
                          onChange={(e) =>
                            setNotificationSettings({
                              ...notificationSettings,
                              slackWebhook: e.target.value,
                            })
                          }
                        />
                      </div>
                    )}

                    <Separator />

                    <div className="flex items-center justify-between">
                      <div className="space-y-0.5">
                        <Label>Critical Alerts Only</Label>
                        <p className="text-sm text-muted-foreground">
                          Only receive notifications for critical severity alerts
                        </p>
                      </div>
                      <Switch
                        checked={notificationSettings.criticalOnly}
                        onCheckedChange={(checked) =>
                          setNotificationSettings({ ...notificationSettings, criticalOnly: checked })
                        }
                      />
                    </div>

                    <div className="space-y-2">
                      <Label>Digest Frequency</Label>
                      <Select
                        value={notificationSettings.digestFrequency}
                        onValueChange={(value) =>
                          setNotificationSettings({ ...notificationSettings, digestFrequency: value })
                        }
                      >
                        <SelectTrigger className="w-[200px]">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="realtime">Real-time</SelectItem>
                          <SelectItem value="hourly">Hourly Digest</SelectItem>
                          <SelectItem value="daily">Daily Digest</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <Separator />

                  <div className="flex justify-end">
                    <Button onClick={handleSaveNotifications}>
                      <Save className="w-4 h-4 mr-2" />
                      Save Changes
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Security Settings */}
            {activeTab === 'security' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="w-5 h-5" />
                    Security Settings
                  </CardTitle>
                  <CardDescription>
                    Configure security and access control settings
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Multi-Factor Authentication (MFA)</Label>
                      <p className="text-sm text-muted-foreground">
                        Require MFA for all users
                      </p>
                    </div>
                    <Switch
                      checked={securitySettings.mfaEnabled}
                      onCheckedChange={(checked) =>
                        setSecuritySettings({ ...securitySettings, mfaEnabled: checked })
                      }
                    />
                  </div>

                  <Separator />

                  <div className="flex items-center justify-between">
                    <div className="space-y-0.5">
                      <Label>Audit Logging</Label>
                      <p className="text-sm text-muted-foreground">
                        Log all user actions for compliance
                      </p>
                    </div>
                    <Switch
                      checked={securitySettings.auditLogging}
                      onCheckedChange={(checked) =>
                        setSecuritySettings({ ...securitySettings, auditLogging: checked })
                      }
                    />
                  </div>

                  <Separator />

                  <div className="space-y-2">
                    <Label htmlFor="sessionTimeout">Session Timeout (minutes)</Label>
                    <Input
                      id="sessionTimeout"
                      type="number"
                      value={securitySettings.sessionTimeout}
                      onChange={(e) =>
                        setSecuritySettings({
                          ...securitySettings,
                          sessionTimeout: parseInt(e.target.value) || 30,
                        })
                      }
                      className="w-[200px]"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label>Password Policy</Label>
                    <Select
                      value={securitySettings.passwordPolicy}
                      onValueChange={(value) =>
                        setSecuritySettings({ ...securitySettings, passwordPolicy: value })
                      }
                    >
                      <SelectTrigger className="w-[200px]">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="basic">Basic (8+ characters)</SelectItem>
                        <SelectItem value="strong">Strong (12+ with symbols)</SelectItem>
                        <SelectItem value="strict">Strict (16+ with complexity)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ipWhitelist">IP Whitelist (comma separated)</Label>
                    <Input
                      id="ipWhitelist"
                      placeholder="192.168.1.0/24, 10.0.0.0/8"
                      value={securitySettings.ipWhitelist}
                      onChange={(e) =>
                        setSecuritySettings({ ...securitySettings, ipWhitelist: e.target.value })
                      }
                    />
                    <p className="text-xs text-muted-foreground">
                      Leave empty to allow all IP addresses
                    </p>
                  </div>

                  <Separator />

                  <div className="flex justify-end">
                    <Button onClick={handleSaveSecurity}>
                      <Save className="w-4 h-4 mr-2" />
                      Save Changes
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Integrations */}
            {activeTab === 'integrations' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Database className="w-5 h-5" />
                    Integrations
                  </CardTitle>
                  <CardDescription>
                    Connect with external services and tools
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {[
                    { name: 'Splunk', status: 'connected', icon: '🔷' },
                    { name: 'Elastic SIEM', status: 'connected', icon: '🟡' },
                    { name: 'Microsoft Sentinel', status: 'disconnected', icon: '🔵' },
                    { name: 'CrowdStrike', status: 'connected', icon: '🔴' },
                    { name: 'Palo Alto Cortex', status: 'disconnected', icon: '🟠' },
                    { name: 'ServiceNow', status: 'connected', icon: '🟢' },
                  ].map((integration) => (
                    <div
                      key={integration.name}
                      className="flex items-center justify-between p-4 rounded-lg border"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-2xl">{integration.icon}</span>
                        <div>
                          <p className="font-medium">{integration.name}</p>
                          <Badge
                            variant={integration.status === 'connected' ? 'default' : 'secondary'}
                            className={cn(
                              'text-xs',
                              integration.status === 'connected'
                                ? 'bg-green-500/10 text-green-500 border-green-500/30'
                                : ''
                            )}
                          >
                            {integration.status}
                          </Badge>
                        </div>
                      </div>
                      <Button variant="outline" size="sm">
                        {integration.status === 'connected' ? 'Configure' : 'Connect'}
                      </Button>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* API Keys */}
            {activeTab === 'api' && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Key className="w-5 h-5" />
                    API Keys
                  </CardTitle>
                  <CardDescription>
                    Manage API keys for programmatic access
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex justify-end">
                    <Button>
                      <Key className="w-4 h-4 mr-2" />
                      Generate New Key
                    </Button>
                  </div>

                  <div className="space-y-3">
                    {[
                      { name: 'Production API Key', created: '2024-01-15', lastUsed: '2 hours ago', status: 'active' },
                      { name: 'Development Key', created: '2024-02-01', lastUsed: '5 days ago', status: 'active' },
                      { name: 'CI/CD Integration', created: '2024-01-20', lastUsed: 'Never', status: 'inactive' },
                    ].map((key, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between p-4 rounded-lg border"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <p className="font-medium">{key.name}</p>
                            <Badge
                              variant={key.status === 'active' ? 'default' : 'secondary'}
                              className={cn(
                                'text-xs',
                                key.status === 'active'
                                  ? 'bg-green-500/10 text-green-500 border-green-500/30'
                                  : ''
                              )}
                            >
                              {key.status}
                            </Badge>
                          </div>
                          <p className="text-sm text-muted-foreground">
                            Created: {key.created} · Last used: {key.lastUsed}
                          </p>
                        </div>
                        <div className="flex gap-2">
                          <Button variant="outline" size="sm">
                            <RefreshCw className="w-4 h-4 mr-1" />
                            Rotate
                          </Button>
                          <Button variant="outline" size="sm" className="text-red-500 hover:text-red-500">
                            Revoke
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </ScrollArea>
        </div>
      </div>
    </div>
  );
}
